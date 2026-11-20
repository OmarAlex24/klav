import AuthenticationServices
import SwiftUI

/// The AutoFill entry point (ADR 0018 §4). iOS calls one of the `prepare…`
/// methods, then shows this controller.
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private lazy var model = CredentialModel(context: extensionContext)

    override func viewDidLoad() {
        super.viewDidLoad()
        model.attach(extensionContext)
        let host = UIHostingController(rootView: CredentialView().environmentObject(model))
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
        // The app being filled went to the background with the sheet up.
        NotificationCenter.default.addObserver(forName: .NSExtensionHostDidEnterBackground, object: nil,
                                               queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.model.disappear() }
        }
        NotificationCenter.default.addObserver(forName: .NSExtensionHostWillEnterForeground, object: nil,
                                               queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.model.appear() }
        }
    }

    /// Dismissed (swiped down or cancelled by iOS): drop the keys.
    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        model.disappear()
    }

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        model.begin(.passwords(services: serviceIdentifiers.map(\.identifier)))
    }

    /// A page asked for a passkey and the person picked Klav in iOS's
    /// sheet: the site's passkeys first, then its logins.
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier],
                                        requestParameters: ASPasskeyCredentialRequestParameters) {
        model.begin(.passkeys(services: serviceIdentifiers.map(\.identifier),
                              rpId: requestParameters.relyingPartyIdentifier,
                              clientDataHash: requestParameters.clientDataHash,
                              allowed: requestParameters.allowedCredentials))
    }

    /// A page creates a passkey and the person chose Klav (ADR 0020 §11):
    /// saved on this iPhone without network, uploaded by the app.
    override func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest) {
        guard let request = registrationRequest as? ASPasskeyCredentialRequest,
              let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else {
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }
        // Klav's passkeys are ES256 only (ADR 0020 §2). An empty list: the
        // site named none, and ES256 is WebAuthn's default.
        let algorithms = request.supportedAlgorithms
        guard algorithms.isEmpty || algorithms.contains(.ES256) else {
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }
        model.begin(.register(PasskeyAsk(
            rpId: identity.relyingPartyIdentifier, userName: identity.userName,
            userHandle: identity.userHandle, clientDataHash: request.clientDataHash,
            exclude: (request.excludedCredentials ?? []).map(\.credentialID))))
    }

    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        model.begin(.codes(services: serviceIdentifiers.map(\.identifier)))
    }

    /// Never without the person: the vault opens only with Face ID. So a
    /// login saved for a subdomain (ADR 0025 §2) is never filled here either:
    /// the sheet lists it apart and the person picks it. A passkey too:
    /// Face ID is its user verification (ADR 0020 §8).
    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        extensionContext.cancelRequest(withError: ASExtensionError(.userInteractionRequired))
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        if credentialRequest.type == .passkeyAssertion,
           let request = credentialRequest as? ASPasskeyCredentialRequest,
           let passkey = request.credentialIdentity as? ASPasskeyCredentialIdentity {
            model.begin(.passkey(rpId: passkey.relyingPartyIdentifier, credentialId: passkey.credentialID,
                                 clientDataHash: request.clientDataHash))
            return
        }
        let identity = credentialRequest.credentialIdentity
        let id = identity.recordIdentifier ?? ""
        let service = identity.serviceIdentifier.identifier
        if credentialRequest.type == .oneTimeCode {
            model.begin(.code(id: id, service: service))
        } else {
            model.begin(.password(id: id, service: service))
        }
    }
}
