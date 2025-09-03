name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  release:
    name: Create Release
    runs-on: ubuntu-latest
    env:
      GEMINI_API_KEY_1: ${{ secrets.GEMINI_API_KEY_1 }}
      GEMINI_API_KEY_2: ${{ secrets.GEMINI_API_KEY_2 }}
      GEMINI_API_KEY_3: ${{ secrets.GEMINI_API_KEY_3 }}
      GEMINI_API_KEY_4: ${{ secrets.GEMINI_API_KEY_4 }}
      GEMINI_API_KEY_5: ${{ secrets.GEMINI_API_KEY_5 }}
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      with:
        fetch-depth: 0

    - name: Set up Go
      uses: actions/setup-go@v4
      with:
        go-version: '1.21'

    - name: Run GoReleaser
      uses: goreleaser/goreleaser-action@v4
      with:
        version: latest
        args: release --clean
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

    - name: Upload wordlists to release
      run: |
        zip -r wordlists.zip wordlists/

    - name: Upload additional assets
      uses: svenstaro/upload-release-action@v2
      with:
        repo_token: ${{ secrets.GITHUB_TOKEN }}
        file: wordlists.zip
        asset_name: wordlists.zip
        tag: ${{ github.ref }}
        overwrite: true
