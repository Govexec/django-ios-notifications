# -*- coding: utf-8 -*-
import socket
import struct
import errno
import json
import sys
from binascii import hexlify, unhexlify

from django.db import models
from django.conf import settings
from django.utils.functional import cached_property

try:
    from django.utils.timezone import now as dt_now
except ImportError:
    import datetime
    dt_now = datetime.datetime.now

from django_fields.fields import EncryptedCharField
import OpenSSL

from .exceptions import NotificationPayloadSizeExceeded, InvalidPassPhrase

from apns_clerk import *
from raven.contrib.django.raven_compat.models import client as raven_client


def chunks(l, n):
    """
    Yield successive n-sized chunks from l.
    """
    for i in xrange(0, len(l), n):
        yield l[i:i + n]


class BaseService(models.Model):
    """
    A base service class intended to be subclassed.
    """
    name = models.CharField(max_length=255)
    hostname = models.CharField(max_length=255)
    PORT = 0  # Should be overriden by subclass
    connection = None

    def _connect(self, certificate, private_key, passphrase=None):
        """
        Establishes an encrypted SSL socket connection to the service.
        After connecting the socket can be written to or read from.
        """
        # ssl in Python < 3.2 does not support certificates/keys as strings.
        # See http://bugs.python.org/issue3823
        # Therefore pyOpenSSL which lets us do this is a dependancy.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
        args = [OpenSSL.crypto.FILETYPE_PEM, private_key]
        if passphrase is not None:
            args.append(str(passphrase))
        try:
            pkey = OpenSSL.crypto.load_privatekey(*args)
        except OpenSSL.crypto.Error:
            raise InvalidPassPhrase
        context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
        context.use_certificate(cert)
        context.use_privatekey(pkey)
        self.connection = OpenSSL.SSL.Connection(context, sock)
        self.connection.connect((self.hostname, self.PORT))
        self.connection.set_connect_state()
        self.connection.do_handshake()

    def _disconnect(self):
        """
        Closes the SSL socket connection.
        """
        if self.connection is not None:
            self.connection.shutdown()
            self.connection.close()

    class Meta:
        abstract = True


class APNService(BaseService):
    """
    Represents an Apple Notification Service either for live
    or sandbox notifications.

    `private_key` is optional if both the certificate and key are provided in
    `certificate`.
    """
    certificate = models.TextField()
    private_key = models.TextField()
    passphrase = EncryptedCharField(null=True, blank=True, help_text='Passphrase for the private key')

    PORT = 2195
    fmt = '!cH32sH%ds'

    @cached_property
    def news_alerts_setting(self):
        try:
            return self.settings.get(slug="enabled_news_alerts")
        except AppSetting.DoesNotExist:
            return None

    @cached_property
    def digest_alerts_setting(self):
        try:
            return self.settings.get(slug="enabled_digest_alerts")
        except AppSetting.DoesNotExist:
            return None

    @cached_property
    def has_news_alerts_setting(self):
        return self.news_alerts_setting is not None

    @cached_property
    def has_digest_alerts_setting(self):
        return self.digest_alerts_setting is not None

    def available_devices(self):
        return self.device_set.filter(is_active=True)

    def permitted_devices(self, notification):
        devices = self.available_devices()

        # Reduce list to opted in users
        if notification.has_article and self.has_news_alerts_setting:
            enabled_permissions = (
                self.news_alerts_setting.
                    device_settings.
                    filter(raw_value="true")
            )

            devices = devices.filter(settings__in=enabled_permissions)
        elif notification.has_digest and self.has_digest_alerts_setting:
            enabled_permissions = (
                self.digest_alerts_setting.
                    device_settings.
                    filter(raw_value="true")
            )

            devices = devices.filter(settings__in=enabled_permissions)

        return devices

    def _connect(self):
        """
        Establishes an encrypted SSL socket connection to the service.
        After connecting the socket can be written to or read from.
        """
        return super(APNService, self)._connect(self.certificate, self.private_key, self.passphrase)

    def push_notification_to_devices(self, notification, devices=None, chunk_size=100):
        """
        Sends the specific notification to devices.
        if `devices` is not supplied, all devices in the `APNService`'s device
        list will be sent the notification.
        """
        if devices is None:
            devices = self.permitted_devices(notification)

        """
        Modified Push Process
        """

        # begin session
        self.session = Session()

        # cycle through in batches of `100`
        for devices_chunk in chunks(devices, 100):

            tokens = []
            for device in devices_chunk:
                tokens.append(device.token)

            message = Message(tokens, sound="default", badge=0, alert=notification.message, **notification.extra)

            self._write_message_with_apnsclient(message, devices_chunk)

    def _write_message_with_apnsclient(self, message, devices):

        # start with all devices in "complete" list. remove as necessary.
        # convert to list: attempting to avoid deadlock in "set_devices_last_notified_at"
        complete_devices = list(devices[:])
        fail_devices = []
        retry_devices = []

        con = self.session.get_connection(address=(self.hostname, 2195), cert_string=self.certificate, key_string=self.private_key)

        srv = APNs(con)
        res = srv.send(message)

        # Check failures. Check codes in APNs reference docs.
        for token, reason in res.failed.items():
            code, errmsg = reason

            # Log with sentry
            raven_client.captureMessage(
                "APNs Failure - Reason:%s - Device:%s" % (errmsg, token)
            )

            # Disable device
            for device in devices:
                if device.token == token:
                    complete_devices.remove(device)

                    device.is_active = False
                    device.save()

            print "Device faled: {0}, reason: {1}".format(token, errmsg)

        # Check failures not related to devices.
        for code, errmsg in res.errors:

            # Log with sentry
            raven_client.captureMessage("APNs Failure - Error:%s" % errmsg)

            print "Error: ", errmsg

        # Check if there are tokens that can be retried
        if res.needs_retry():
            # repeat with retry_message
            retry_message = res.retry()

            # add retried devices to "retry_devices"
            for token in retry_message.tokens:
                for device in complete_devices:
                    if device.token == token:
                        retry_devices.append(device)
            # remove retried devices from "complete_devices"
            for device in retry_devices:
                complete_devices.remove(device)

            # retry message
            self._write_message_with_apnsclient(retry_message, retry_devices)

        # set date of last message for "complete_devices"
        self.set_devices_last_notified_at(complete_devices)

    def _write_message(self, notification, devices, chunk_size):
        """
        Writes the message for the supplied devices to
        the APN Service SSL socket.
        """
        if not isinstance(notification, Notification):
            raise TypeError('notification should be an instance of ios_notifications.models.Notification')

        if not isinstance(chunk_size, int) or chunk_size < 1:
            raise ValueError('chunk_size must be an integer greater than zero.')

        payload = notification.payload

        # Split the devices into manageable chunks.
        # Chunk sizes being determined by the `chunk_size` arg.
        device_length = devices.count() if isinstance(devices, models.query.QuerySet) else len(devices)
        chunks = [devices[i:i + chunk_size] for i in xrange(0, device_length, chunk_size)]

        for index in xrange(len(chunks)):
            chunk = chunks[index]
            self._connect()

            for device in chunk:
                if not device.is_active:
                    continue
                try:
                    self.connection.send(self.pack_message(payload, device))
                except (OpenSSL.SSL.WantWriteError, socket.error) as e:
                    if isinstance(e, socket.error) and isinstance(e.args, tuple) and e.args[0] != errno.EPIPE:
                        raise e  # Unexpected exception, raise it.
                    self._disconnect()
                    i = chunk.index(device)
                    self.set_devices_last_notified_at(chunk[:i])
                    # Start again from the next device.
                    # We start from the next device since
                    # if the device no longer accepts push notifications from your app
                    # and you send one to it anyways, Apple immediately drops the connection to your APNS socket.
                    # http://stackoverflow.com/a/13332486/1025116
                    self._write_message(notification, chunk[i + 1:])

            self._disconnect()

            self.set_devices_last_notified_at(chunk)

        if notification.pk or notification.persist:
            notification.last_sent_at = dt_now()
            notification.save()

    def set_devices_last_notified_at(self, devices):
        # Rather than do a save on every object,
        # fetch another queryset and use it to update
        # the devices in a single query.
        # Since the devices argument could be a sliced queryset
        # we can't rely on devices.update() even if devices is
        # a queryset object.

        try:
            Device.objects.filter(pk__in=[d.pk for d in devices]).update(last_notified_at=dt_now())
        except:
            # catchall for deadlock; should not occur, but notifications are too important to be allowed to fail\
            try:
                exc_info = sys.exc_info()
                raven_client.captureException(exc_info)
            finally:
                del exc_info

    def pack_message(self, payload, device):
        """
        Converts a notification payload into binary form.
        """
        if len(payload) > 256:
            raise NotificationPayloadSizeExceeded
        if not isinstance(device, Device):
            raise TypeError('device must be an instance of ios_notifications.models.Device')

        msg = struct.pack(self.fmt % len(payload), chr(0), 32, unhexlify(device.token), len(payload), payload)
        return msg

    def __unicode__(self):
        return self.name

    class Meta:
        unique_together = ('name', 'hostname')


class Notification(models.Model):
    """
    Represents a notification which can be pushed to an iOS device.
    """
    service = models.ForeignKey(APNService)
    message = models.CharField(max_length=200, blank=True, help_text='Alert message to display to the user. Leave empty if no alert should be displayed to the user.')
    badge = models.PositiveIntegerField(null=True, blank=True, help_text='New application icon badge number. Set to None if the badge number must not be changed.')
    sound = models.CharField(max_length=30, blank=True, help_text='Name of the sound to play. Leave empty if no sound should be played.')
    created_at = models.DateTimeField(auto_now_add=True)
    last_sent_at = models.DateTimeField(null=True, blank=True)
    custom_payload = models.CharField(max_length=240, blank=True, help_text='JSON representation of an object containing custom payload.')

    def __init__(self, *args, **kwargs):
        self.persist = getattr(settings, 'IOS_NOTIFICATIONS_PERSIST_NOTIFICATIONS', True)
        super(Notification, self).__init__(*args, **kwargs)

    def __unicode__(self):
        return u'%s%s%s' % (self.message, ' ' if self.message and self.custom_payload else '', self.custom_payload)

    @property
    def has_article(self):
        return self.extra and "article_id" in self.extra

    @property
    def has_digest(self):
        return self.extra and "issue_id" in self.extra

    @property
    def extra(self):
        """
        The extra property is used to specify custom payload values
        outside the Apple-reserved aps namespace
        http://developer.apple.com/library/mac/#documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/ApplePushService/ApplePushService.html#//apple_ref/doc/uid/TP40008194-CH100-SW1
        """
        return json.loads(self.custom_payload) if self.custom_payload else None

    @extra.setter
    def extra(self, value):
        if value is None:
            self.custom_payload = ''
        else:
            if not isinstance(value, dict):
                raise TypeError('must be a valid Python dictionary')
            self.custom_payload = json.dumps(value)  # Raises a TypeError if can't be serialized

    def push_to_all_devices(self):
        """
        Pushes this notification to all active devices using the
        notification's related APN service.
        """
        self.service.push_notification_to_devices(self)

    def is_valid_length(self):
        """
        Determines if a notification payload is a valid length.

        returns bool
        """
        return len(self.payload) <= 256

    @property
    def payload(self):
        aps = {}
        if self.message:
            aps['alert'] = self.message
        if self.badge is not None:
            aps['badge'] = self.badge
        if self.sound:
            aps['sound'] = self.sound
        message = {'aps': aps}
        extra = self.extra
        if extra is not None:
            message.update(extra)
        payload = json.dumps(message, separators=(',', ':'))
        return payload


class Device(models.Model):
    """
    Represents an iOS device with unique token.
    """
    token = models.CharField(max_length=64, blank=False, null=False)
    is_active = models.BooleanField(default=True)
    deactivated_at = models.DateTimeField(null=True, blank=True)
    service = models.ForeignKey(APNService)
    users = models.ManyToManyField(getattr(settings, 'AUTH_USER_MODEL', 'auth.User'), null=True, blank=True, related_name='ios_devices')
    added_at = models.DateTimeField(auto_now_add=True)
    last_notified_at = models.DateTimeField(null=True, blank=True)
    platform = models.CharField(max_length=30, blank=True, null=True)
    display = models.CharField(max_length=30, blank=True, null=True)
    os_version = models.CharField(max_length=20, blank=True, null=True)

    def push_notification(self, notification):
        """
        Pushes a ios_notifications.models.Notification instance to an the device.
        For more details see http://developer.apple.com/library/mac/#documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/ApplePushService/ApplePushService.html
        """
        if not isinstance(notification, Notification):
            raise TypeError('notification should be an instance of ios_notifications.models.Notification')

        notification.service.push_notification_to_devices(notification, [self])

    @cached_property
    def settings_dict(self):
        settings = self.settings.all().select_related("app_setting")

        return {s.app_setting.slug: s for s in settings}

    def update_device_settings(self, new_settings):
        for slug, value in new_settings.iteritems():
            setting = self.settings_dict.get(slug)

            if not setting:
                try:
                    app_setting = AppSetting.objects.get(service=self.service, slug=slug)

                    setting = DeviceSetting()
                    setting.app_setting = app_setting
                except AppSetting.DoesNotExist:
                    raven_client.captureMessage(
                        "Invalid setting.  Does not exist for this app.",
                        extra={
                            "token": self.token,
                            "invalid_setting": {
                                slug: value,
                            },
                        }
                    )
                    continue

            setting.device = self
            setting.value = value
            setting.save()

    def __unicode__(self):
        return self.token

    class Meta:
        unique_together = ('token', 'service')


class FeedbackService(BaseService):
    """
    The service provided by Apple to inform you of devices which no longer have your app installed
    and to which notifications have failed a number of times. Use this class to check the feedback
    service and deactivate any devices it informs you about.

    https://developer.apple.com/library/ios/#documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/CommunicatingWIthAPS/CommunicatingWIthAPS.html#//apple_ref/doc/uid/TP40008194-CH101-SW3
    """
    apn_service = models.ForeignKey(APNService)

    PORT = 2196

    fmt = '!lh32s'

    def _connect(self):
        """
        Establishes an encrypted socket connection to the feedback service.
        """
        return super(FeedbackService, self)._connect(self.apn_service.certificate, self.apn_service.private_key, self.apn_service.passphrase)

    def call(self):
        """
        Calls the feedback service and deactivates any devices the feedback service mentions.
        """
        self._connect()
        device_tokens = []
        try:
            while True:
                data = self.connection.recv(38)  # 38 being the length in bytes of the binary format feedback tuple.
                timestamp, token_length, token = struct.unpack(self.fmt, data)
                device_token = hexlify(token)
                device_tokens.append(device_token)
        except OpenSSL.SSL.ZeroReturnError:
            # Nothing to receive
            pass
        finally:
            self._disconnect()
        devices = Device.objects.filter(token__in=device_tokens, service=self.apn_service)
        devices.update(is_active=False, deactivated_at=dt_now())
        return devices.count()

    def __unicode__(self):
        return self.name

    class Meta:
        unique_together = ('name', 'hostname')


class AppSetting(models.Model):
    DATA_TYPE_BOOLEAN = 'boolean'
    DATA_TYPE_STRING = 'string'

    DATA_TYPE_CHOICES = (
        (DATA_TYPE_BOOLEAN, 'Boolean'),
        (DATA_TYPE_STRING, 'String'),
    )

    service = models.ForeignKey(APNService, related_name="settings")
    slug = models.SlugField(max_length=100)
    data_type = models.CharField(max_length=30, choices=DATA_TYPE_CHOICES)

    @property
    def is_boolean(self):
        return self.data_type == AppSetting.DATA_TYPE_BOOLEAN

    @property
    def is_string(self):
        return self.data_type == AppSetting.DATA_TYPE_STRING

    class Meta:
        unique_together = ('service', 'slug')

    def __unicode__(self):
        return self.slug

class DeviceSetting(models.Model):
    VALID_TRUE_VALUES = ["true", "1", "yes"]
    VALID_FALSE_VALUES = ["false", "0", "no"]

    app_setting = models.ForeignKey(AppSetting, related_name="device_settings")
    device = models.ForeignKey(Device, related_name="settings")
    raw_value = models.CharField(max_length=500)

    @property
    def value(self):
        return_value = json.loads(self.raw_value)

        if self.app_setting.is_boolean:
            return return_value
        elif self.app_setting.is_string:
            return return_value
        else:
            raise NotImplementedError("Type `{}` not implemented".format(self.data_type))

    @value.setter
    def value(self, new_value):
        if self.app_setting.is_boolean:
            if not isinstance(new_value, bool):
                if new_value.lower() in DeviceSetting.VALID_TRUE_VALUES:
                    new_value = True
                elif new_value.lower() in DeviceSetting.VALID_FALSE_VALUES:
                    new_value = False
                else:
                    raise ValueError("Invalid boolean")
        elif self.app_setting.is_string:
            if not isinstance(new_value, (str, unicode)):
                raise ValueError("Invalid string")
        else:
            raise NotImplementedError("Type `{}` not implemented".format(self.data_type))

        self.raw_value = json.dumps(new_value)

    def __unicode__(self):
        if self.app_setting:
            return u"{}: {}".format(self.device_id, self.app_setting.slug)
        else:
            return unicode(self.device_id)

    class Meta:
        unique_together = ('app_setting', 'device')
