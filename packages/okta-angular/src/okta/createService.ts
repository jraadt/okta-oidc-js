import { Injector } from '@angular/core';
import { OktaConfig } from './models/okta.config';
import { OktaAuthService } from './services/okta.service';
import { ApplicationRef } from '@angular/core';

export function createOktaService(config: OktaConfig, injector: Injector, applicationRef: ApplicationRef) {
  return new OktaAuthService(config, injector, applicationRef);
}
