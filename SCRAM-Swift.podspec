#
# Be sure to run `pod lib lint SCRAM-Swift.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see https://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'SCRAM-Swift'
  s.version          = '0.0.4'
  s.summary          = 'A SCRAM implementation for Swift. Supports SHA1, SHA256 and SHA512.'

# This description is used to generate tags and improve search results.
#   * Think: What does it do? Why did you write it? What is the focus?
#   * Try to keep it short, snappy and to the point.
#   * Write the description between the DESC delimiters below.
#   * Finally, don't worry about the indent, CocoaPods strips it!

  s.description      = <<-DESC
A basic SCRAM implementation in Swift. Supports SHA1, SHA256 and SHA512.
                       DESC

  s.homepage         = 'https://github.com/alinradut/SCRAM-Swift'
  # s.screenshots     = 'www.example.com/screenshots_1', 'www.example.com/screenshots_2'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Alin Radut' => 'cocoapods at alinradut dot ro' }
  s.source           = { :git => 'https://github.com/alinradut/SCRAM-Swift.git', :tag => s.version.to_s }
  # s.social_media_url = 'https://twitter.com/<TWITTER_USERNAME>'

  s.swift_version = '5.0'
  s.ios.deployment_target = '8.0'
  
  s.source_files = 'SCRAM-Swift/Classes/**/*'
  
  # s.resource_bundles = {
  #   'SCRAM-Swift' => ['SCRAM-Swift/Assets/*.png']
  # }

  # s.public_header_files = 'Pod/Classes/**/*.h'
  # s.frameworks = 'UIKit', 'MapKit'
  # s.dependency 'AFNetworking', '~> 2.3'
end
