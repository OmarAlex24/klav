import XCTest
@testable import Klav

/// Two wordings that were wrong: Spanish «hasta las 1:15» (it is «la» at
/// one o'clock), and the pause promising Touch ID on a Mac without it.
final class WordingTests: XCTestCase {
    private func es() throws -> Bundle {
        try XCTUnwrap(Bundle(for: MacModel.self).path(forResource: "es", ofType: "lproj").flatMap(Bundle.init(path:)))
    }

    func testOneOClockIsToldApart() {
        for clock in ["1:15 PM", "1:00 a.m.", "01:15", "1:59 p. m."] {
            XCTAssertTrue(TaskWords.atOne(clock), clock)
        }
        for clock in ["10:15 PM", "11:00 a.m.", "13:15", "21:05", "12:01 AM", "2:15 p.m.", "00:15", ""] {
            XCTAssertFalse(TaskWords.atOne(clock), clock)
        }
    }

    /// Spanish takes «la» at one o'clock and «las» at every other hour.
    func testSpanishSaysLaAtOneOClock() throws {
        let es = try es()
        func say(_ key: String, _ args: CVarArg...) -> String {
            String(format: es.localizedString(forKey: key, value: "∅", table: nil), arguments: args)
        }
        XCTAssertEqual(say("task.until.atOne", "1:15 p.m."), "hasta la 1:15 p.m.")
        XCTAssertEqual(say("until %@", "2:15 p.m."), "hasta las 2:15 p.m.")
        XCTAssertEqual(say("task.lasts.atOne", "2 h", "1:15 p.m."), "2 h desde que apruebes, hasta la 1:15 p.m.")
        XCTAssertEqual(say("%@ from approval, until %@", "2 h", "3:15 p.m."), "2 h desde que apruebes, hasta las 3:15 p.m.")
        XCTAssertEqual(say("task.left.atOne", "10 min", "1:15 p.m."), "Quedan 10 min · termina a la 1:15 p.m.")
        XCTAssertEqual(say("%@ left · ends at %@", "10 min", "4:15 p.m."), "Quedan 10 min · termina a las 4:15 p.m.")
    }

    /// English reads the same either way.
    func testEnglishIsTheSameAtAnyHour() {
        let one = Date(timeIntervalSince1970: 0)
        XCTAssertTrue(TaskWords.until(0).hasPrefix("until "))
        XCTAssertTrue(TaskWords.lasts(60, now: one).contains(" from approval, until "))
        XCTAssertTrue(TaskWords.left(until: 600_000, now: one).contains(" left · ends at "))
    }

    /// At one o'clock the keyed variants resolve: never a raw key on screen.
    func testOneOClockShowsWordsNotKeys() throws {
        let one = try XCTUnwrap(Calendar.current.date(bySettingHour: 1, minute: 15, second: 0, of: Date()))
        let end = Int64(one.timeIntervalSince1970 * 1000)
        XCTAssertTrue(TaskWords.atOne(TaskWords.clock(end)), TaskWords.clock(end))
        let before = one.addingTimeInterval(-600)
        for (text, phrase) in [(TaskWords.until(end), "until "),
                               (TaskWords.lasts(600, now: before), " from approval, until "),
                               (TaskWords.left(until: end, now: before), " left · ends at ")] {
            XCTAssertFalse(text.contains("task."), text)
            XCTAssertTrue(text.contains(phrase), text)
            XCTAssertTrue(text.contains(TaskWords.clock(end)), text)
        }
    }

    func testThePauseSaysWhatResumingAsks() throws {
        let es = try es()
        for key in ["Stops every agent of your account at once, on this Mac and everywhere else, until the time is up or you resume. Pausing asks nothing; resuming asks for your master password.",
                    "Agents can use Klav again once you enter your master password."] {
            let spanish = es.localizedString(forKey: key, value: "∅", table: nil)
            XCTAssertNotEqual(spanish, "∅", key)
            XCTAssertTrue(spanish.contains("contraseña maestra"), spanish)
            XCTAssertFalse(spanish.contains("Touch ID"), spanish)
        }
    }
}
