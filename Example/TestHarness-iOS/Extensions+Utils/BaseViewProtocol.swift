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

import UIKit

protocol BaseViewProtocol: AnyObject {
    func pop()
    func pop(completion: @escaping () -> Void)
    func push(_ viewController: UIViewController)
    func present(_ viewController: UIViewController)
    func presentError(title: String, message: String)
    func presentAlert(_ actions: [ActionSheetActionViewModel], title: String?)
    func presentAlert(_ actions: [ActionSheetActionViewModel], title: String?, message: String?)
    func presentActionSheet(_ actions: [ActionSheetActionViewModel], title: String?, sourceButton: UIBarButtonItem?)
    func updateData()
    func getSingleLineText(title: String?, message: String?, placeholder: String?, completion: @escaping (String) -> Void)
    func confirmAction(title: String?, message: String?, yesActionStyle: UIAlertAction.Style, completion: @escaping () -> Void)
}

extension BaseViewProtocol where Self: UIViewController {
    func presentError(title: String, message: String) {
        let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
        alert.addAction(.init(title: "Ok", style: .default, handler: nil))
        present(alert)
    }

    func presentAlert(_ actions: [ActionSheetActionViewModel], title: String?) {
        presentAlert(actions, title: title, message: nil)
    }

    func presentAlert(_ actions: [ActionSheetActionViewModel], title: String?, message: String?) {
        let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
        actions.map { action in
            UIAlertAction(title: action.title, style: action.style, handler: { _ in action.handler?() })
        }.forEach(alert.addAction)
        present(alert)
    }

    func presentActionSheet(_ actions: [ActionSheetActionViewModel], title: String?, sourceButton: UIBarButtonItem?) {
        let actionSheet = UIAlertController(title: title, message: nil, preferredStyle: .actionSheet)
        actions.map { action in
            let alertAction = UIAlertAction(title: action.title, style: action.style, handler: { _ in action.handler?() })
            alertAction.isEnabled = action.isEnabled
            return alertAction
        }.forEach(actionSheet.addAction)
        actionSheet.popoverPresentationController?.barButtonItem = sourceButton
        present(actionSheet)
    }

    func getSingleLineText(title: String?, message: String?, placeholder: String?, completion: @escaping (String) -> Void) {
        let alertController = UIAlertController(title: title, message: message, preferredStyle: .alert)
        alertController.addTextField { textField in
            textField.keyboardType = .default
            textField.autocorrectionType = .no
            textField.autocapitalizationType = .none
            textField.placeholder = placeholder
        }
        let okAction = UIAlertAction(title: "Ok", style: .default, handler: { [weak alertController] _ in
            if let text = alertController?.textFields?.first?.text {
                completion(text)
            }
        })
        let cancelAction = UIAlertAction(title: "Cancel", style: .cancel, handler: nil)
        [okAction, cancelAction].forEach(alertController.addAction)
        present(alertController)
    }

    func pop() {
        navigationController?.popViewController(animated: true)
    }

    func pop(completion: @escaping () -> Void) {
        navigationController?.popViewController(animated: true, completion: completion)
    }

    func push(_ viewController: UIViewController) {
        navigationController?.pushViewController(viewController, animated: true)
    }

    func present(_ viewController: UIViewController) {
        present(viewController, animated: true)
    }

    func confirmAction(title: String?, message: String?, yesActionStyle: UIAlertAction.Style, completion: @escaping () -> Void) {
        let yesAction = ActionSheetActionViewModel(title: "Yes", style: yesActionStyle, handler: completion)
        let noAction = ActionSheetActionViewModel(title: "No")
        presentAlert([yesAction, noAction], title: title, message: message)
    }

    func updateData() {}
}

class ActionSheetActionViewModel {
    let title: String
    let style: UIAlertAction.Style
    let isEnabled: Bool
    let handler: (() -> Void)?

    init(title: String, style: UIAlertAction.Style = .default, isEnabled: Bool = true, handler: (() -> Void)? = nil) {
        self.title = title
        self.style = style
        self.isEnabled = isEnabled
        self.handler = handler
    }
}
