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

protocol StoryboardController {
    static var storyboardIdentifier: String { get }

    static func loadFromStoryboard(storyboardName: String) -> Self
}

extension StoryboardController where Self: UIViewController {

    static var storyboardIdentifier: String {
        return String(describing: Self.self)
    }

    static func loadFromStoryboard(storyboardName: String) -> Self {
        let storyboard = UIStoryboard(name: storyboardName, bundle: Bundle(for: Self.self))
        let viewController = storyboard.instantiateViewController(withIdentifier: storyboardIdentifier)
        if viewController == nil {
            fatalError("Missing initial view controller. Please double check the storyboard: \(storyboardName)")
        }
        return viewController as! Self
    }

    func embedInNavigation() -> UINavigationController { UINavigationController(rootViewController: self) }
}
