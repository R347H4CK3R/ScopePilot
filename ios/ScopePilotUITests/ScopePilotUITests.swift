import XCTest

final class ScopePilotUITests: XCTestCase {
    func testBundledWorkspaceLoadsAndNavigationWorks() {
        continueAfterFailure = false
        let app = XCUIApplication()
        app.launch()
        let web = app.webViews.firstMatch
        XCTAssertTrue(web.waitForExistence(timeout: 15), "Bundled workspace must create a WebView")
        let overview = web.buttons["Overview"]
        XCTAssertTrue(overview.waitForExistence(timeout: 15), "Local HTML and JavaScript must load")
        XCTAssertTrue(web.buttons["Add a program"].exists)
        web.buttons["Discover"].tap()
        XCTAssertTrue(web.buttons["Refresh public listings ↗"].waitForExistence(timeout: 5))
        web.buttons["Research"].tap()
        XCTAssertTrue(web.buttons["Add your first program →"].waitForExistence(timeout: 5))
        web.buttons["Reports"].tap()
        XCTAssertTrue(web.buttons["Start an analysis →"].waitForExistence(timeout: 5))
        overview.tap()
        XCTAssertTrue(web.buttons["Add a program"].waitForExistence(timeout: 5))
        let screenshot = XCTAttachment(screenshot: app.screenshot())
        screenshot.name = "ScopePilot iPhone overview"
        screenshot.lifetime = .keepAlways
        add(screenshot)
    }
}
