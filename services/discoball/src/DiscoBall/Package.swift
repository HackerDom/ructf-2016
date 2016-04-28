import PackageDescription

let package = Package(
    dependencies: [
        .Package(url: "../COpenGL", majorVersion: 1)
    ]
)
