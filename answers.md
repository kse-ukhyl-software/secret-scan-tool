# Answers
1. Why do some rules have an `entropy` threshold and others don't?
    - Rules, that are looking for secrets with specific patterns, doesn't need one, because there is nearly no chance to identify some string as a secret.
    Example: AWS Access Key with it's AKIA start
    
    - On the other hand, there is generic secrets, that might look like some hash or base64 text, that's why we need some entropy to decided whether it is a secret or just some text.
    Example: API key of some small product
2. What is the purpose of `secret_group` and which rules use it?
    Sometimes, to find a secret, regex needs to match whole code line, but the entropy check needs to be run only on the secret itself.
    That's why we need secret_group, that would tell us, which capture group contains actual secret for entropy check.
3.  How does the keyword pre-filter improve performance?
    Regex is computationaly heavy, especially when the pattern is big and needs to be compared with a huge amount of code lines.
    With keyword pre-filter we can eliminate regex scanning of regular language statements (e.g., for or while loop opening, closed scope '}' )
4. Why are lock files and binary formats excluded?
    Lock files are auto-generated and contain lots of hashes, that might be interpreted as secrets, which is a lot of false positives.
    Binary format isn't human readable, which makes scanning with regex slow and useless
5. Why is `"test"` in the `allowlist_stopwords` list?
    To prevent scanner treating fake credentials, made for testing, as real one
6. What is `workflow_call` and how is it different from `workflow_dispatch`?
    `workflow_call` allows workflow to be triggered by another workflow, which makes it reusable for automated CI
    `workflow_dispatch` is a manual trigger, that adds button in Github Actions for users to trigger it 
7. Why does the job need `packages: write` permission?
    To push Docker image into GHCR (GitHub Container Registry)
8. Why does the workflow only log in to the registry when `push` is `true`?
    Security reasons. If it runs only tests or dry build, then there is no need to give the workflow push access.
9. What is the benefit of GHA cache (`cache-from`/`cache-to: type=gha`)?
    It reuses Docker layers from previous runs if possible, instead of rebuilding them every time.
10. Why is `python:3.12-slim` used instead of the full image?
    `slim` version has minimal packages, which reduces image size, makes it faster to build and pull
11. What is the difference between `ENTRYPOINT` and `CMD` here?
    `ENTRYPOINT` is fixed executable, that container will run always
    `CMD` sets arguments for that executable, overriding default `CMD` config
12. How does volume mounting (`-v`) allow scanning files outside the container?
    Docker containers are running in isolation.
    By mounting repository folder to specific folder inside the container, it can access it from that folder
# Secret Detect Image
https://github.com/kse-ukhyl-software/secret-scan-tool/actions/runs/23685707101
https://github.com/kse-ukhyl-software/secret-scan-tool/blob/main/.github/workflows/ci.yml
# Secret scanning for microservices
https://github.com/kse-ukhyl-software/simple-go-service-a/actions/runs/23685842590
https://github.com/kse-ukhyl-software/simple-go-service-a/blob/main/.github/workflows/release.yaml

https://github.com/kse-ukhyl-software/my-app/actions/runs/23685976597
https://github.com/kse-ukhyl-software/my-app/blob/main/.github/workflows/ci-main.yaml