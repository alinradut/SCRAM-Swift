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
        let data = self.data(of: length)
        return String(data: data, encoding: .ascii)!
    }
}
