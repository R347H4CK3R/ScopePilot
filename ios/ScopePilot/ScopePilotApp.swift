import SwiftUI
import WebKit

@main struct ScopePilotApp: App {
    var body: some Scene { WindowGroup { Workspace().preferredColorScheme(.dark).background(Color(red: 0.035, green: 0.078, blue: 0.086)) } }
}
struct Workspace: UIViewControllerRepresentable {
    func makeUIViewController(context: Context) -> WorkspaceController { WorkspaceController() }
    func updateUIViewController(_ controller: WorkspaceController, context: Context) {}
}
final class WorkspaceController: UIViewController, WKScriptMessageHandler, WKNavigationDelegate, WKUIDelegate {
    private var web: WKWebView!
    override func viewDidLoad() {
        super.viewDidLoad()
        let configuration = WKWebViewConfiguration()
        configuration.userContentController.add(self, name: "scopepilot")
        web = WKWebView(frame: .zero, configuration: configuration)
        web.navigationDelegate = self
        web.uiDelegate = self
        web.isOpaque = false
        web.backgroundColor = UIColor(red: 0.035, green: 0.078, blue: 0.086, alpha: 1)
        view = web
        if let url = Bundle.main.url(forResource: "index", withExtension: "html", subdirectory: "Web") {
            web.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
        }
    }
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        let url = navigationAction.request.url
        let root = Bundle.main.resourceURL?.appendingPathComponent("Web").standardizedFileURL.path ?? ""
        decisionHandler(url?.isFileURL == true && url!.standardizedFileURL.path.hasPrefix(root + "/") ? .allow : .cancel)
    }
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.frameInfo.isMainFrame, message.frameInfo.request.url?.isFileURL == true,
              let body = message.body as? [String: String] else { return }
        if body["action"] == "open", let raw = body["url"], let url = URL(string: raw), url.scheme == "https", url.host != nil, url.user == nil, url.password == nil {
            UIApplication.shared.open(url)
        } else if body["action"] == "export", let text = body["text"], text.utf8.count <= 200_000 {
            let sheet = UIActivityViewController(activityItems: [text], applicationActivities: nil)
            sheet.popoverPresentationController?.sourceView = view
            sheet.popoverPresentationController?.sourceRect = CGRect(x: view.bounds.midX, y: view.bounds.midY, width: 1, height: 1)
            present(sheet, animated: true)
        }
    }
    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        let alert = UIAlertController(title: "ScopePilot", message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in completionHandler(false) })
        alert.addAction(UIAlertAction(title: "Confirm", style: .default) { _ in completionHandler(true) })
        present(alert, animated: true)
    }
    deinit { web?.configuration.userContentController.removeScriptMessageHandler(forName: "scopepilot") }
}
