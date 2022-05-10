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

import Foundation
import UIKit

protocol ActivityIndicatorViewProtocol {
    func showActivityIndicator()
    func hideActivityIndicator()
}

extension ActivityIndicatorViewProtocol where Self: UIViewController {
    
    func showActivityIndicator() {
        hideActivityIndicator()
        let activityIndicatorView = ActivityIndicatorView()
        activityIndicatorView.display(in: self.view)
    }
    
    func hideActivityIndicator() {
        let activityIndicatorView = self.view?.subviews.compactMap { $0 as? ActivityIndicatorView}.first
        activityIndicatorView?.hide()
    }
}

class ActivityIndicatorView: UIActivityIndicatorView {

    convenience init() {
        self.init(style: .large)
        self.translatesAutoresizingMaskIntoConstraints = false
        self.isHidden = true
    }

    func display(in view: UIView) {
        if superview == nil {
            view.addSubview(self)
            centerYAnchor.constraint(equalTo: view.centerYAnchor).isActive = true
            centerXAnchor.constraint(equalTo: view.centerXAnchor).isActive = true
        }
        if !isAnimating {
            startAnimating()
        }
        isHidden = false
        view.isUserInteractionEnabled = false
    }

    func hide() {
        if isAnimating {
            stopAnimating()
        }
        isHidden = true
        superview?.isUserInteractionEnabled = true
        if let _ = superview {
            removeFromSuperview()
        }
    }
}
