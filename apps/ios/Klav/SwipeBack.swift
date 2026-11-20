import UIKit

/// The screens hide the navigation bar and draw their own back button, and a
/// hidden bar also turns off UIKit's edge swipe back. This gives it back to
/// every navigation stack: the swipe starts only when there is a screen to
/// go back to, so the root never swallows the gesture. SwiftUI may reset the
/// recognizer while it lays the stack out, so it is claimed again each time.
/// From iOS 26 the swipe back also starts anywhere on the screen (the
/// content pop recognizer), and a hidden bar turns that one off too.
extension UINavigationController: @retroactive UIGestureRecognizerDelegate {
    override open func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        var pops = [interactivePopGestureRecognizer]
        if #available(iOS 26, *) { pops.append(interactiveContentPopGestureRecognizer) }
        for pop in pops.compactMap({ $0 }) {
            pop.isEnabled = true
            pop.delegate = self
        }
    }

    public func gestureRecognizerShouldBegin(_ gestureRecognizer: UIGestureRecognizer) -> Bool {
        viewControllers.count > 1
    }
}
