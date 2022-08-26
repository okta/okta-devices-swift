/*
* Copyright (c) 2022-Present, Okta, Inc. and/or its affiliates. All rights reserved.
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
import OktaLogger

class MailService: NSObject, MFMailComposeViewControllerDelegate {

    func sendFileLogs(fileLogger: OktaLoggerFileLogger, nav: UINavigationController) {
        DispatchQueue.global(qos: .userInitiated).async {
            fileLogger.getLogs { data in
                var joined = Data()
                data.forEach { joined.append($0) }
                DispatchQueue.main.async {
                    let mailAttachment = MailAttachment(data: joined, fileName: "logs.txt", mimeType: "text/plain")
                    self.sendFileLogs(recipients: [], subject: "PushSDK Sample iOS logs", fileLog: mailAttachment, nav: nav)
                }
            }
        }
    }

    private func sendFileLogs(recipients: [String], subject: String, fileLog: MailAttachment, nav: UINavigationController) {
        guard MFMailComposeViewController.canSendMail() else {
            let alert = UIAlertController(title: nil, message: "Please set up an e-mail account first", preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "Ok", style: .default))
            nav.present(alert, animated: true, completion: nil)
            return
        }
        let composer = MFMailComposeViewController()
        composer.mailComposeDelegate = self
        composer.setToRecipients(recipients)
        composer.setSubject(subject)
        composer.setMessageBody("", isHTML: true)
        composer.addAttachmentData(fileLog.data, mimeType: fileLog.mimeType, fileName: fileLog.fileName)
        nav.present(composer, animated: true)
    }

    func mailComposeController(_ controller: MFMailComposeViewController, didFinishWith result: MFMailComposeResult, error: Error?) {
        controller.dismiss(animated: true)
    }
}

struct MailAttachment {
    let data: Data
    let fileName: String
    let mimeType: String
}
