/*
 * Copyright (c) 2017-Present, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

import { Inject, Injectable, Injector, ApplicationRef } from '@angular/core';
import {
  assertIssuer,
  assertClientId,
  assertRedirectUri,
} from '@okta/configuration-validation';

import { OKTA_CONFIG, OktaConfig, AuthRequiredFunction } from '../models/okta.config';
import { UserClaims } from '../models/user-claims';
import { TokenManager, AccessToken, IDToken } from '../models/token-manager';

import packageInfo from '../packageInfo';

/**
 * Import the okta-auth-js library
 */
import OktaAuth from '@okta/okta-auth-js';
import { Observable, Observer } from 'rxjs';
import { first } from 'rxjs/operators';

@Injectable()
export class OktaAuthService {
    private oktaAuth: Promise<OktaAuth>;
    private config: OktaConfig;
    private observers: Observer<boolean>[];
    $authenticationState: Observable<boolean>;

    constructor(@Inject(OKTA_CONFIG) config: OktaConfig, private injector: Injector, private applicationRef: ApplicationRef) {
      this.observers = [];

      /**
       * Cache the auth config.
       */
      this.config = Object.assign({}, config);
      this.config.scopes = this.config.scopes || ['openid', 'email'];

      // Automatically enter login flow if session has expired or was ended outside the application
      // The default behavior can be overriden by setting your own `onSessionExpired` function on the OktaConfig
      if (!this.config.onSessionExpired) {
        this.config.onSessionExpired = this.login.bind(this);
      }

      /**
       * Scrub scopes to ensure 'openid' is included
       */

      this.scrubScopes(this.config.scopes);

      // Assert Configuration
      assertIssuer(this.config.issuer, this.config.testing);
      assertClientId(this.config.clientId);
      assertRedirectUri(this.config.redirectUri);

      this.oktaAuth = new Promise((resolve, reject) => {
        this.applicationRef.isStable.pipe(first(stable => stable)).subscribe(_ => {
          const oktaAuthInstance = new OktaAuth(this.config);
          oktaAuthInstance.userAgent = `${packageInfo.name}/${packageInfo.version} ${oktaAuthInstance.userAgent}`;
          resolve(oktaAuthInstance);
        });
      });

      this.$authenticationState = new Observable((observer: Observer<boolean>) => { this.observers.push(observer); });
    }

    login(fromUri?: string, additionalParams?: object) {
      this.setFromUri(fromUri);
      const onAuthRequired: AuthRequiredFunction | undefined = this.config.onAuthRequired;
      if (onAuthRequired) {
        return onAuthRequired(this, this.injector);
      }
      return this.loginRedirect(undefined, additionalParams);
    }

    async getTokenManager(): Promise<TokenManager> {
      return (await this.oktaAuth).tokenManager;
    }

    /**
     * Checks if there is an access token OR an id token
     * A custom method may be provided on config to override this logic
     */
    async isAuthenticated(): Promise<boolean> {
      // Support a user-provided method to check authentication
      if (this.config.isAuthenticated) {
        return (this.config.isAuthenticated)();
      }

      const accessToken = await this.getAccessToken();
      const idToken = await this.getIdToken();
      return !!(accessToken || idToken);
    }

    private async emitAuthenticationState(state: boolean) {
      this.observers.forEach(observer => observer.next(state));
    }

    /**
     * Returns the current accessToken in the tokenManager.
     */
    async getAccessToken(): Promise<string | undefined>  {
      try {
        const accessToken: AccessToken = await (await this.oktaAuth).tokenManager.get('accessToken') as AccessToken;
        if (accessToken == null) {
          return undefined;
        }
        return accessToken.accessToken;
      } catch (err) {
        // The user no longer has an existing SSO session in the browser.
        // (OIDC error `login_required`)
        // Ask the user to authenticate again.
        return undefined;
      }
    }

    /**
     * Returns the current idToken in the tokenManager.
     */
    async getIdToken(): Promise<string | undefined> {
      try {
        const idToken: IDToken = await (await this.oktaAuth).tokenManager.get('idToken') as IDToken;
        return idToken.idToken;
      } catch (err) {
        // The user no longer has an existing SSO session in the browser.
        // (OIDC error `login_required`)
        // Ask the user to authenticate again.
        return undefined;
      }
    }

    /**
     * Returns user claims from the /userinfo endpoint if an
     * accessToken is provided or parses the available idToken.
     */
    async getUser(): Promise<UserClaims|undefined> {
      const auth = await this.oktaAuth;
      const accessToken: AccessToken = await auth.tokenManager.get('accessToken') as AccessToken;
      const idToken: IDToken = await auth.tokenManager.get('idToken') as IDToken;
      if (!accessToken || !idToken) {
        // Returns raw claims from idToken if there is no accessToken.
        return idToken ? idToken.claims : undefined;
      }
      return auth.token.getUserInfo();
    }

    /**
     * Returns the configuration object used.
     */
    getOktaConfig(): OktaConfig {
      return this.config;
    }

    /**
     * Launches the login redirect.
     * @param fromUri
     * @param additionalParams
     */
    async loginRedirect(fromUri?: string, additionalParams?: object) {
      if (fromUri) {
        this.setFromUri(fromUri);
      }

      const params = Object.assign({
        scopes: this.config.scopes,
        responseType: this.config.responseType
      }, additionalParams);

      return (await this.oktaAuth).token.getWithRedirect(params); // can throw
    }

    /**
     * Silently retrieve token.
     * @param additionalParams
     */
    async loginSilent(additionalParams?: object) {
      try {
        const auth = await this.oktaAuth;

        const params = Object.assign({
          scopes: this.config.scopes,
          responseType: this.config.responseType
        }, additionalParams);

        const tokens = await auth.token.getWithoutPrompt(params);

        for (let a = 0; a < tokens.length; a++) {
          if (tokens[a].accessToken) {
            auth.tokenManager.add('accessToken', tokens[a]);
          }
          if (tokens[a].idToken) {
            auth.tokenManager.add('idToken', tokens[a]);
          }
        }

        if (await this.isAuthenticated()) {
          this.emitAuthenticationState(true);
        }

        return tokens;
      } catch (err) {
        // The user no longer has an existing SSO session in the browser.
        // (OIDC error `login_required`)
        // Ask the user to authenticate again.
        return undefined;
      }
    }

    /**
     * Stores the intended path to redirect after successful login.
     * @param uri
     * @param queryParams
     */
    setFromUri(fromUri?: string) {
      // Use current location if fromUri was not passed
      fromUri = fromUri || window.location.href;
      // If a relative path was passed, convert to absolute URI
      if (fromUri.charAt(0) === '/') {
        fromUri = window.location.origin + fromUri;
      }
      sessionStorage.setItem('referrerPath', fromUri);
    }

    /**
     * Returns the referrer path from localStorage or app root.
     */
    getFromUri(): string {
      const fromUri = sessionStorage.getItem('referrerPath') || window.location.origin;
      sessionStorage.removeItem('referrerPath');
      return fromUri;
    }

    /**
     * Parses the tokens from the callback URL.
     */
    async handleAuthentication(): Promise<void> {
      const auth = await this.oktaAuth;
      const res = await auth.token.parseFromUrl();
      const tokens = res.tokens;
      if (tokens.accessToken) {
        auth.tokenManager.add('accessToken', tokens.accessToken as AccessToken);
      }
      if (tokens.idToken) {
        auth.tokenManager.add('idToken', tokens.idToken as IDToken);
      }
      if (await this.isAuthenticated()) {
        this.emitAuthenticationState(true);
      }
    }

    /**
     * Clears the user session in Okta and removes
     * tokens stored in the tokenManager.
     * @param options
     */
    async logout(options?: any): Promise<void> {
      let redirectUri = null;
      options = options || {};
      if (typeof options === 'string') {
        redirectUri = options;
        // If a relative path was passed, convert to absolute URI
        if (redirectUri.charAt(0) === '/') {
          redirectUri = window.location.origin + redirectUri;
        }
        options = {
          postLogoutRedirectUri: redirectUri
        };
      }
      await (await this.oktaAuth).signOut(options);
      this.emitAuthenticationState(false);
    }

    /**
     * Scrub scopes to ensure 'openid' is included
     * @param scopes
     */
    scrubScopes(scopes: string[]): void {
      if (scopes.indexOf('openid') >= 0) {
        return;
      }
      scopes.unshift('openid');
    }
}
