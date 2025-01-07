from .oauth2 import OAuthAuthenticator
from quetz.config import Config
import httpx

class GithubAuthenticator(OAuthAuthenticator):
    """Use Github account to authenticate users with Quetz.

    To enable add the following to the configuration file:

    .. code::

      [github]
      client_id = "fde330aef1fbe39991"
      client_secret = "03728444a12abff17e9444fd231b4379d58f0b"

    You can obtain ``client_id`` and ``client_secret`` by registering your
    application with Github at this URL:
    `<https://github.com/settings/applications/new>`_.
    """

    provider = "github"
    collect_emails = False
    collect_orgs = False
    orgs = []

    # oauth client params
    access_token_url = "https://github.com/login/oauth/access_token"
    authorize_url = "https://github.com/login/oauth/authorize"
    api_base_url = "https://api.github.com/"
    scope = ""

    # endpoint urls
    validate_token_url = "user"
    revoke_url = "https://github.com/settings/connections/applications/{client_id}"

    async def userinfo(self, request, token):
        resp = await self.client.get("user", token=token)
        profile = resp.json()

        if self.collect_emails:
            emails = await self.client.get("user/emails", token=token)
            profile["emails"] = emails.json()
        
        if self.collect_orgs:
          orgs = await self.client.get("user/orgs", token=token)
          org_resp_json = orgs.json()
          org_names = [org['login'] for org in org_resp_json]
          profile["orgs"] = orgs.json()

          for name in self.orgs:
            if name not in org_names:
              raise Exception("Auth Failed")
            
        return profile

    def configure(self, config):
        if config.configured_section("github"):
            self.client_id = config.github_client_id
            self.client_secret = config.github_client_secret
            self.is_enabled = True

            self.collect_orgs = config.github_collect_orgs
            self.orgs = config.github_orgs
            if config.configured_section("users"):
                self.collect_emails = config.users_collect_emails

            scope = ""
            if self.collect_orgs:
              scope += "read:org"
            if self.collect_emails:
              scope += " user:email"

            self.scope = scope

        else:
            self.is_enabled = False

        # call the configure of base class to set default_channel and default role
        super().configure(config)
