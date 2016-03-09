# -*- coding: utf-8 -*-

try:
    from django.conf.urls import patterns, url
except ImportError:  # deprecated since Django 1.4
    from django.conf.urls.defaults import patterns, url

from django import forms
from django.contrib import admin
from django.template.response import TemplateResponse
from django.shortcuts import get_object_or_404

from .models import Device, Notification, APNService, FeedbackService, DeviceSetting, AppSetting
from .forms import APNServiceForm


class AppSettingInline(admin.TabularInline):
    model = AppSetting


class DeviceSettingForm(forms.ModelForm):
    value = forms.CharField(max_length=500, label="Value")

    def __init__(self, **kwargs):
        super(DeviceSettingForm, self).__init__(**kwargs)

        if self.instance.id:
            self.fields["value"].initial = self.instance.value

    class Meta:
        model = DeviceSetting
        exclude = ('raw_value',)


class DeviceSettingInline(admin.TabularInline):
    model = DeviceSetting
    form = DeviceSettingForm

    fields = ('app_setting', 'value')


class APNServiceAdmin(admin.ModelAdmin):
    list_display = ('name', 'hostname')
    form = APNServiceForm

    inlines = [
        AppSettingInline,
    ]


class DeviceAdmin(admin.ModelAdmin):
    fields = ('token', 'is_active', 'service')
    list_display = ('token', 'is_active', 'service', 'last_notified_at', 'platform', 'display', 'os_version', 'added_at', 'deactivated_at')
    list_filter = ('is_active', 'last_notified_at', 'added_at', 'deactivated_at')
    search_fields = ('token', 'platform')

    inlines = [
        DeviceSettingInline,
    ]

    def save_formset(self, request, form, formset, change):
        super(DeviceAdmin, self).save_formset(request, form, formset, change)

        for f in formset.forms:
            obj = f.instance
            if hasattr(obj, "app_setting") and obj.app_setting:
                obj.value = f.cleaned_data.get("value")
                obj.save()


class NotificationAdmin(admin.ModelAdmin):
    exclude = ('last_sent_at',)
    list_display = ('message', 'badge', 'sound', 'custom_payload', 'created_at', 'last_sent_at',)
    list_filter = ('created_at', 'last_sent_at')
    search_fields = ('message', 'custom_payload')
    list_display_links = ('message', 'custom_payload',)

    def get_urls(self):
        urls = super(NotificationAdmin, self).get_urls()
        notification_urls = patterns('',
                                     url(r'^(?P<id>\d+)/push-notification/$', self.admin_site.admin_view(self.admin_push_notification),
                                     name='admin_push_notification'),)
        return notification_urls + urls

    def admin_push_notification(self, request, **kwargs):
        notification = get_object_or_404(Notification, **kwargs)
        num_devices = 0
        if request.method == 'POST':
            service = notification.service
            available_devices = service.available_devices().count()
            permitted_devices = service.permitted_devices(notification).count()
            notification.service.push_notification_to_devices(notification)
        return TemplateResponse(
            request,
            'admin/ios_notifications/notification/push_notification.html',
            {
                'notification': notification,
                'available_devices': available_devices,
                'permitted_devices': permitted_devices,
                'sent': request.method == 'POST'
            },
            current_app='ios_notifications'
        )

admin.site.register(Device, DeviceAdmin)
admin.site.register(Notification, NotificationAdmin)
admin.site.register(APNService, APNServiceAdmin)
admin.site.register(FeedbackService)
