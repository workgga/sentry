from __future__ import absolute_import

from django.core.urlresolvers import reverse
from django.db.models import F
from django.http import HttpResponse
from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers, status
from rest_framework.response import Response

from sentry import features, roles
from sentry.api.bases.organization import OrganizationEndpoint, OrganizationAuthProviderPermission
from sentry.api.exceptions import ResourceDoesNotExist
from sentry.api.serializers import serialize
from sentry.models import AuditLogEntryEvent, AuthProvider, OrganizationMember
from sentry.plugins.base.response import Response as PluginResponse
from sentry.utils import db
from sentry.utils.http import absolute_uri

ERR_NO_SSO = _('The SSO feature is not enabled for this organization.')

OK_PROVIDER_DISABLED = _('SSO authentication has been disabled.')


class AuthSettingsSerializer(serializers.Serializer):
    require_link = serializers.BooleanField()
    default_role = serializers.ChoiceField(choices=roles.get_choices())


class OrganizationAuthProviderEndpoint(OrganizationEndpoint):
    permission_classes = (OrganizationAuthProviderPermission, )

    def get(self, request, organization):
        """
        Retrieve an Organization's Auth Provider
        ````````````````````````````````````````

        :pparam string organization_slug: the organization short name
        :auth: required
        """
        if not features.has('organizations:sso', organization, actor=request.user):
            return Response(ERR_NO_SSO, status=status.HTTP_403_FORBIDDEN)

        try:
            auth_provider = AuthProvider.objects.get(
                organization=organization,
            )
        except AuthProvider.DoesNotExist:
            # This is a valid state where org does not have an auth provider
            # configured, make sure we respond with a 20x
            return Response(status=status.HTTP_204_NO_CONTENT)

        # provider configure view can either be a template or a http response
        provider = auth_provider.get_provider()

        view = provider.get_configure_view()
        response = view(request, organization, auth_provider)

        if isinstance(response, HttpResponse):
            return response
        elif isinstance(response, PluginResponse):
            response = response.render(
                request, {
                    'auth_provider': auth_provider,
                    'organization': organization,
                    'provider': provider,
                }
            )

        pending_links_count = OrganizationMember.objects.filter(
            organization=organization,
            flags=~getattr(OrganizationMember.flags, 'sso:linked'),
        ).count()

        context = {
            'pending_links_count': pending_links_count,
            'login_url': absolute_uri(reverse('sentry-organization-home', args=[organization.slug])),
            'auth_provider': serialize(auth_provider),
            'default_role': organization.default_role,
            'require_link': not auth_provider.flags.allow_unlinked,
            'provider_name': provider.name,
            'content': serialize(response),
        }

        return Response(serialize(context, request.user))

    def put(self, request, organization):
        """
        Update an Auth Provider's settings
        ``````````````````````````````````

        :pparam string organization_slug: the organization short name
        :param boolean require_link: require members to link to SSO
        :param string default_role: set default role
        :auth: required
        """
        if not features.has('organizations:sso', organization, actor=request.user):
            return Response(ERR_NO_SSO, status=status.HTTP_403_FORBIDDEN)

        try:
            auth_provider = AuthProvider.objects.get(
                organization=organization,
            )
        except AuthProvider.DoesNotExist:
            raise ResourceDoesNotExist

        serializer = AuthSettingsSerializer(
            data=request.DATA, partial=True)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        result = serializer.object

        auth_provider.flags.allow_unlinked = not result['require_link']
        auth_provider.save()

        if result.get('default_role'):
            # It seems that `default_role` in `AuthProvider` model is not used
            organization.default_role = result['default_role']
            organization.save()

        self.create_audit_entry(
            request=request,
            organization=organization,
            target_object=auth_provider.id,
            event=AuditLogEntryEvent.SSO_EDIT,
            data=auth_provider.get_audit_log_data(),
        )

        return Response(serialize(auth_provider, request.user))

    def delete(self, request, organization):
        """
        Disable Auth Provider
        `````````````````````

        :pparam string organization_slug: the organization short name
        :auth: required
        """
        if not features.has('organizations:sso', organization, actor=request.user):
            return Response(ERR_NO_SSO, status=status.HTTP_403_FORBIDDEN)

        try:
            auth_provider = AuthProvider.objects.get(
                organization=organization,
            )
        except AuthProvider.DoesNotExist:
            raise ResourceDoesNotExist

        self.create_audit_entry(
            request,
            organization=organization,
            target_object=auth_provider.id,
            event=AuditLogEntryEvent.SSO_DISABLE,
            data=auth_provider.get_audit_log_data(),
        )

        if db.is_sqlite():
            for om in OrganizationMember.objects.filter(organization=organization):
                setattr(om.flags, 'sso:linked', False)
                setattr(om.flags, 'sso:invalid', False)
                om.save()
        else:
            OrganizationMember.objects.filter(
                organization=organization,
            ).update(
                flags=F('flags').bitand(
                    ~getattr(OrganizationMember.flags, 'sso:linked'),
                ).bitand(
                    ~getattr(OrganizationMember.flags, 'sso:invalid'),
                ),
            )

        auth_provider.delete()

        return Response(status=status.HTTP_204_NO_CONTENT)
