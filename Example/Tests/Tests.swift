import XCTest
import SCRAM_Swift

class Tests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testSHA1Vectors() {
        let scram = SCRAM(username: "user", password: "pencil", nonce: "fyko+d2lbbFgONRv9qkxdawL", algorithm: .sha1)
        _ = try! scram.handleInitialServerMessage("cj1meWtvK2QybGJiRmdPTlJ2OXFreGRhd0wzcmZjTkhZSlkxWlZ2V1ZzN2oscz1RU1hDUitRNnNlazhiZjkyLGk9NDA5Ng==")
        XCTAssert(try! scram.handleFinalServerMessage("dj1ybUY5cHFWOFM3c3VBb1pXamE0ZEpSa0ZzS1E9"), "The server signature does not match")
    }
    
    func testSHA1VectorsFail() {
        let scram = SCRAM(username: "user", password: "pencil1", nonce: "fyko+d2lbbFgONRv9qkxdawL", algorithm: .sha1)
        _ = try! scram.handleInitialServerMessage("cj1meWtvK2QybGJiRmdPTlJ2OXFreGRhd0wzcmZjTkhZSlkxWlZ2V1ZzN2oscz1RU1hDUitRNnNlazhiZjkyLGk9NDA5Ng==")
        XCTAssert(try! scram.handleFinalServerMessage("dj1ybUY5cHFWOFM3c3VBb1pXamE0ZEpSa0ZzS1E9") == false, "The server signature does not match")
    }
    
    func testSHA256Vectors() {
        let scram = SCRAM(username: "user", password: "pencil", nonce: "rOprNGfwEbeRWgbNEkqO", algorithm: .sha256)
        _ = try! scram.handleInitialServerMessage("cj1yT3ByTkdmd0ViZVJXZ2JORWtxTyVodllEcFdVYTJSYVRDQWZ1eEZJbGopaE5sRiRrMCxzPVcyMlphSjBTTlk3c29Fc1VFamI2Z1E9PSxpPTQwOTY=")
        XCTAssert(try! scram.handleFinalServerMessage("dj02cnJpVFJCaTIzV3BSUi93dHVwK21NaFVaVW4vZEI1bkxUSlJzamw5NUc0PQ=="), "The server signature does not match")
    }
    
    func testSHA256VectorsFail() {
        let scram = SCRAM(username: "user", password: "pencil1", nonce: "rOprNGfwEbeRWgbNEkqO", algorithm: .sha256)
        _ = try! scram.handleInitialServerMessage("cj1yT3ByTkdmd0ViZVJXZ2JORWtxTyVodllEcFdVYTJSYVRDQWZ1eEZJbGopaE5sRiRrMCxzPVcyMlphSjBTTlk3c29Fc1VFamI2Z1E9PSxpPTQwOTY=")
        XCTAssert(try! scram.handleFinalServerMessage("dj02cnJpVFJCaTIzV3BSUi93dHVwK21NaFVaVW4vZEI1bkxUSlJzamw5NUc0PQ==") == false, "The server signature does not match")
    }
    
    func testNonceGeneration() {
        let nonce = Random.string(of: SCRAM.nonceLength)
        XCTAssert(nonce.count == SCRAM.nonceLength)
    }
}
