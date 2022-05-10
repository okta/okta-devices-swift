/*
* Copyright (c) 2019-Present, Okta, Inc. and/or its affiliates. All rights reserved.
* The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
*
* You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
* WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*
* See the License for the specific language governing permissions and limitations under the License.
*/

import MessageUI

enum MailServiceError {
    case canNotSendMail
    case other(String)
}

protocol MailServiceDelegate: AnyObject {
    func mailServicePresent(_ viewController: UIViewController)
    func mailServiceError(_ error: MailServiceError)
}

struct MailAttachment {
    let data: Data
    let fileName: String
    let mimeType: String
}

protocol MailServiceProtocol: AnyObject {
    var delegate: MailServiceDelegate? { get set }

    func sendMail(subject: String?, body: String?, isHtml: Bool, recepients: [String], attachments: [MailAttachment])
}

class MailService: NSObject, MailServiceProtocol, MFMailComposeViewControllerDelegate {
    weak var delegate: MailServiceDelegate?

    private let canSendMail: () -> Bool

    init(canSendMail: @escaping () -> Bool = MFMailComposeViewController.canSendMail) {
        self.canSendMail = canSendMail
    }

    func sendMail(subject: String?, body: String?, isHtml: Bool, recepients: [String], attachments: [MailAttachment]) {
        guard canSendMail() else {
            delegate?.mailServiceError(.canNotSendMail)
            return
        }
        let composer = MFMailComposeViewController()
        composer.mailComposeDelegate = self
        composer.setToRecipients(recepients)
        composer.setSubject(subject ?? "")
        composer.setMessageBody(body ?? "", isHTML: isHtml)
        attachments.forEach { composer.addAttachmentData($0.data, mimeType: $0.mimeType, fileName: $0.fileName) }
        delegate?.mailServicePresent(composer)
    }

    // MARK: MFMailComposeViewController
    func mailComposeController(_ controller: MFMailComposeViewController, didFinishWith result: MFMailComposeResult, error: Error?) {
        if let error = error {
            controller.dismiss(animated: true) { [weak self] in self?.delegate?.mailServiceError(.other(error.localizedDescription)) }
        }
        controller.dismiss(animated: true)
    }
}
