import { device } from "tns-core-modules/platform";
import { ios as iOSUtils } from "tns-core-modules/utils/utils";
import {
  SignInWithAppleAuthorization,
  SignInWithAppleOptions,
  SignInWithAppleState,
  SignInWithAppleUserDetectionStatus,
  SignInWithAppleCredential
} from "./index";
import jsArrayToNSArray = iOSUtils.collections.jsArrayToNSArray;
import nsArrayToJSArray = iOSUtils.collections.nsArrayToJSArray;

let controller: any /* ASAuthorizationController */;
let delegate: any;
let ASAuthorizationControllerDelegateImpl: any;

declare const ASAuthorizationAppleIDProvider,
  ASAuthorizationController,
  ASAuthorizationControllerDelegate,
  ASAuthorizationScopeEmail,
  ASAuthorizationScopeFullName: any;

export function isSignInWithAppleSupported(): boolean {
  return parseInt(device.osVersion) >= 13;
}

export function getSignInWithAppleState(
  user: string
): Promise<SignInWithAppleState> {
  return new Promise<any>((resolve, reject) => {
    if (!user) {
      reject("The 'user' parameter is mandatory");
      return;
    }

    if (!isSignInWithAppleSupported()) {
      reject("Not supported");
      return;
    }

    const provider = ASAuthorizationAppleIDProvider.new();
    provider.getCredentialStateForUserIDCompletion(user, (
      state: any /* enum: ASAuthorizationAppleIDProviderCredentialState */,
      error: NSError
    ) => {
      if (error) {
        reject(error.localizedDescription);
        return;
      }

      if (state === 1) {
        // ASAuthorizationAppleIDProviderCredential.Authorized
        resolve("AUTHORIZED");
      } else if (state === 2) {
        // ASAuthorizationAppleIDProviderCredential.NotFound
        resolve("NOTFOUND");
      } else if (state === 3) {
        // ASAuthorizationAppleIDProviderCredential.Revoked
        resolve("REVOKED");
      } else {
        // this prolly means a state was added so we need to add it to the plugin
        reject(
          "Invalid state for getSignInWithAppleState: " +
            state +
            ", please report an issue at he plugin repo!"
        );
      }
    });
  });
}

if (isSignInWithAppleSupported()) {
  ASAuthorizationControllerDelegateImpl = (<any>NSObject).extend({
    authorizationControllerDidCompleteWithAuthorization: function(
      controller: any /* ASAuthorizationController */,
      authorization: {
        provider: any;
        credential: SignInWithAppleCredential & {
          accessToken?: NSData;
          authenticatedResponse?: NSHTTPURLResponse;
          authorizationCode?: NSData;
          authorizedScopes?: NSArray<string>;
          identityToken?: NSData;
        };
      }
    ): void {
      if (authorization && authorization.credential) {
        const data: SignInWithAppleAuthorization = {
          provider: authorization.provider,
          credential: {
            // primitive data
            email: authorization.credential.email,
            fullName: authorization.credential.fullName,
            realUserStatus: authorization.credential.realUserStatus,
            state: authorization.credential.state,
            user: authorization.credential.user,
            password: authorization.credential.password
          }
        };
        // then in addition for added convenience, convert some native objects to friendly js
        if (authorization.credential.accessToken) {
          data.credential.accessToken = <string>(<unknown>NSString.alloc()
            .initWithDataEncoding(
              authorization.credential.accessToken,
              NSUTF8StringEncoding
            )
            .toString());
        }
        if (authorization.credential.authorizationCode) {
          data.credential.authorizationCode = <string>(<unknown>NSString.alloc()
            .initWithDataEncoding(
              authorization.credential.authorizationCode,
              NSUTF8StringEncoding
            )
            .toString());
        }
        if (authorization.credential.authorizedScopes) {
          data.credential.authorizedScopes = nsArrayToJSArray(
            authorization.credential.authorizedScopes
          );
        }
        if (authorization.credential.identityToken) {
          data.credential.identityToken = <string>(<unknown>NSString.alloc()
            .initWithDataEncoding(
              authorization.credential.identityToken,
              NSUTF8StringEncoding
            )
            .toString());
        }
        this.resolve(data);
      } else {
        this.reject("auth error: no credential returned.");
      }
    },
    authorizationControllerDidCompleteWithError: function(
      controller: any /* ASAuthorizationController */,
      error: NSError
    ): void {
      this.reject(error.localizedDescription);
    }
  }, {
    protocols: [ASAuthorizationControllerDelegate]
  });
  ASAuthorizationControllerDelegateImpl['createWithPromise'] = function(resolve, reject) {
    const delegate = ASAuthorizationControllerDelegateImpl.new();
    delegate.resolve = resolve;
    delegate.reject = reject;
    return delegate;
  };
}

export function signInWithApple(
  options?: SignInWithAppleOptions
): Promise<SignInWithAppleAuthorization> {
  return new Promise<any>((resolve, reject) => {
    if (!isSignInWithAppleSupported()) {
      reject("Not supported");
      return;
    }

    const provider = ASAuthorizationAppleIDProvider.new();
    const request = provider.createRequest();

    if (options && options.user) {
      request.user = options.user;
    }

    if (options && options.scopes) {
      const nsArray = NSMutableArray.new();
      options.scopes.forEach(s => {
        if (s === "EMAIL") {
          nsArray.addObject(ASAuthorizationScopeEmail);
        } else if (s === "FULLNAME") {
          nsArray.addObject(ASAuthorizationScopeFullName);
        } else {
          console.log(
            "Unsupported scope: " + s + ", use either EMAIL or FULLNAME"
          );
        }
      });
      request.requestedScopes = nsArray;
    }

    controller = ASAuthorizationController.alloc().initWithAuthorizationRequests(
      jsArrayToNSArray([request])
    );
    controller.delegate = delegate = ASAuthorizationControllerDelegateImpl.createWithPromise(
      resolve,
      reject
    );
    controller.performRequests();
  });
}
