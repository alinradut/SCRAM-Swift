//
//  Random.swift
//  SCRAM-Swift
//
//  Created by Alin Radut on 18/06/2020.
//

import Foundation

public struct Random {
    
    /// Generate `size` random bytes.
    /// - Parameter size: Number of random bytes to generate
    /// - Returns: Data
    public static func data(of size: Int) -> Data {
        var data = Data(count: size)
        let result = data.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, size, $0.baseAddress!)
        }
        guard result == errSecSuccess else {
            fatalError("Error while generating random bytes.")
        }
        return data
    }
    
    /// Generate a random string of `length` characters
    /// - Parameter length: Number of characters to generate.
    /// - Returns: String
    public static func string(of length: Int) -> String {
        let randomBytes = [UInt8](self.data(of: length))
        let characters: [Character] = stride(from: 33, to: 127, by: 1).map({ Character(UnicodeScalar($0 as UInt8)) })
        let output: [Character] = randomBytes.map({ characters[Int($0) % characters.count] })
        return String(output)
    }
}
