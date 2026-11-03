// CI for p3dx_gov_layer — check, build, scan, publish, then hand the image tag to GitOps.
//
// Same model as the dx-authz-go Jenkinsfile: CI lives here, CD lives in dx-gitops (Argo CD), and the only
// handoff is the image tag. On a build of DEPLOY_BRANCH this pipeline pushes
// ghcr.io/datakaveri/p3dx-gov-layer:<semver>-<sha> and (when GITOPS_ENABLED) opens a PR against dx-gitops
// that bumps image.tag in environments/dev/p3dx-gov-layer.yaml. Merging that PR is what deploys.
// Jenkins never touches the cluster.
//
// Job type: plain Pipeline ("Pipeline script from SCM"), NOT Multibranch. Such a job has no BRANCH_NAME,
// only GIT_BRANCH (e.g. "origin/deploy_updates"), so the branch is derived from that. Branch Specifier: */deploy_updates.
// Other branches (e.g. main, version-0.1.0) run every check but do not push or bump.
//
// The checks (see dx-azure-deployment/docs/cicd-pipeline-guide.html). One tool per job:
//   1 unit tests (-race, coverage gate, HTML coverage report)   2 compile + golangci-lint (incl. vet, gofmt)
//   3 go.mod guard (+ tidy)   4 commitlint + pre-commit   5 SonarQube quality gate   6 SAST (Semgrep)
//   7 secrets (gitleaks)   8 SCA (Trivy fs)   9 licenses (Trivy)   10 Dockerfile/IaC (Trivy config)
//   11 image scan (Trivy: vulnerabilities + image config)   12 SBOM + Cosign signature + SLSA provenance
//   13 push (+ X.Y.Z tag when the commit has a vX.Y.Z git tag) + bump dx-gitops
// Gates: blocking unless marked UNSTABLE below (security findings start UNSTABLE, as in dx-authz-go;
// tighten by removing the catchError once the backlog is cleared).
//
// Agent needs only: docker, git, curl, trivy (as for dx-authz-go). Every other tool runs from a pinned image.
//
// Jenkins credentials expected:
//   datakaveri-ghcr      username/password — push to ghcr.io (password = PAT with write:packages)
//   datakaveri-gitops    username/password — GitHub user + PAT that can push branches / open PRs on dx-gitops
//   sonarqube            SonarQube server configured in Jenkins (Manage Jenkins > System), only if SONAR_ENABLED
//   cosign-key           secret file (cosign.key) + cosign-password secret text — only if COSIGN_ENABLED

// "origin/main" / "refs/heads/main" / "main" -> "main"
def branchName() {
  return (env.GIT_BRANCH ?: '').replaceFirst(/^refs\/heads\//, '').replaceFirst(/^origin\//, '')
}

def isDeployBranch() {
  return branchName() == env.DEPLOY_BRANCH
}

// Run a shell step inside the pinned Go image (workspace mounted at the same path).
def inGo(String script) {
  docker.image(env.GO_IMAGE).inside("-e HOME=${env.WORKSPACE}/.home -e GOFLAGS=-buildvcs=false -e GOCACHE=${env.WORKSPACE}/.cache/go-build -e GOMODCACHE=${env.WORKSPACE}/.cache/gomod") {
    sh script
  }
}

pipeline {
  environment {
    SERVICE         = 'p3dx-gov-layer'
    IMAGE_REPO      = 'ghcr.io/datakaveri/p3dx-gov-layer'
    REGISTRY_URI    = 'https://ghcr.io'
    REGISTRY_CRED   = 'datakaveri-ghcr'
    DEPLOY_BRANCH   = 'deploy_updates'             // the branch whose builds are published
    GITOPS_ENABLED  = 'false'                      // 'true' once environments/dev/p3dx-gov-layer.yaml exists in dx-gitops
    GITOPS_REPO     = 'datakaveri/dx-gitops'
    GITOPS_BRANCH   = 'dev'
    GITOPS_CRED     = 'datakaveri-gitops'
    GIT_HASH        = GIT_COMMIT.take(7)

    // Pinned tool images (bump deliberately, never :latest)
    GO_IMAGE        = 'golang:1.26-bookworm'       // matches go.mod / Dockerfile
    GOLANGCI_IMAGE  = 'golangci/golangci-lint:v2.14.0'   // v2: needs Go >= 1.26 support; config is .golangci.yml version 2
    LINT_BASELINE   = 'b0130a2256e233fecad283cadaddcd4a22092e3f'   // deploy_updates when CI was added; see Static checks
    NODE_IMAGE      = 'node:22-alpine'
    PRECOMMIT_IMAGE = 'python:3.12-bookworm'   // needs git (pre-commit); -slim has none
    SEMGREP_IMAGE   = 'semgrep/semgrep:1.140.0'
    GITLEAKS_IMAGE  = 'zricethezav/gitleaks:v8.28.0'
    SYFT_IMAGE      = 'anchore/syft:v1.33.0'
    COSIGN_IMAGE    = 'gcr.io/projectsigstore/cosign:v2.6.1'

    // Gates and switches
    COVERAGE_MIN    = '25'      // % total statement coverage, blocking; measured 26.5% on 2026-10-22 — raise as tests grow
    COVERAGE_TARGET = '80'      // % coverage goal: below it the build is UNSTABLE (blocking once COVERAGE_MIN reaches it)
    SONAR_ENABLED   = 'false'   // 'true' once a SonarQube server is configured in Jenkins
    COSIGN_ENABLED  = 'false'   // 'true' once cosign-key / cosign-password credentials exist
    DOCKER_BUILDKIT = '1'
  }

  agent {
    node {
      label 'slave1'
    }
  }

  options {
    timeout(time: 45, unit: 'MINUTES')
    disableConcurrentBuilds()
    buildDiscarder(logRotator(numToKeepStr: '20'))
  }

  stages {

    // Always runs — shows which branch Jenkins checked out, i.e. why the deploy-only stages did or did not run.
    stage('Build info') {
      steps {
        echo "GIT_BRANCH=${env.GIT_BRANCH} -> branch=${branchName()} deploy=${isDeployBranch()} commit=${env.GIT_COMMIT}"
        sh 'mkdir -p reports .home .cache'
      }
    }

    // 7. Secrets first: a leaked credential stops the build before anything else runs with the code.
    stage('Secrets') {
      steps {
        script {
          def range = env.GIT_PREVIOUS_SUCCESSFUL_COMMIT ? "${env.GIT_PREVIOUS_SUCCESSFUL_COMMIT}..HEAD" : 'HEAD~1..HEAD'
          docker.image(env.GITLEAKS_IMAGE).inside('--entrypoint=') {
            sh """
              git config --global --add safe.directory "\$PWD" 2>/dev/null || true
              gitleaks git --log-opts="${range}" --redact --report-format json --report-path reports/gitleaks.json --exit-code 1 .
            """
          }
        }
      }
    }

    // 4. Conventional Commits on the commits new to this build, then the repo's pre-commit hooks.
    stage('Commit hygiene') {
      steps {
        script {
          def from = env.GIT_PREVIOUS_SUCCESSFUL_COMMIT ?: sh(script: 'git rev-parse HEAD~1 2>/dev/null || git rev-list --max-parents=0 HEAD', returnStdout: true).trim()
          // UNSTABLE for now: the current history is not Conventional Commits yet. Make it blocking
          // (drop catchError) once the team has adopted the format.
          catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE', message: 'Commit messages are not Conventional Commits (feat:, fix:, chore: ...)') {
            docker.image(env.NODE_IMAGE).inside("-e HOME=${env.WORKSPACE}/.home") {
              sh """
                npm install --no-save --silent @commitlint/cli@19 @commitlint/config-conventional@19 >/dev/null
                npx --no-install commitlint --extends @commitlint/config-conventional --from ${from} --to HEAD --verbose
              """
            }
          }
          if (fileExists('.pre-commit-config.yaml')) {
            // SKIP: hooks that need docker or Go inside this python container, or that another stage already
            // covers with its one tool (hadolint-docker: Dockerfile / IaC, gofmt + go-mod-guard: Static checks,
            // gitleaks + detect-private-key: Secrets).
            docker.image(env.PRECOMMIT_IMAGE).inside("-e HOME=${env.WORKSPACE}/.home -e PRE_COMMIT_HOME=${env.WORKSPACE}/.cache/pre-commit -e SKIP=hadolint-docker,gofmt,go-mod-guard,gitleaks,detect-private-key") {
              sh '''
                pip install --quiet --user pre-commit==4.3.0
                git config --global --add safe.directory "$PWD"
                "$HOME/.local/bin/pre-commit" run --all-files --show-diff-on-failure
              '''
            }
          } else {
            echo 'No .pre-commit-config.yaml in the repo — pre-commit skipped'
          }
        }
      }
    }

    // 2 + 3. Compile, lint (golangci-lint also runs go vet and the gofmt check), and the go.mod guard.
    stage('Static checks') {
      steps {
        script {
          inGo '''
            go build ./...
            # 3. no relative replace directive (a path on someone's laptop)
            if grep -nE '^\\s*replace\\s+.*=>\\s*\\.{1,2}/' go.mod; then echo "relative replace in go.mod"; exit 1; fi
            # go.mod/go.sum must already be tidy
            cp go.mod /tmp/go.mod.orig; cp go.sum /tmp/go.sum.orig
            go mod tidy
            if ! cmp -s go.mod /tmp/go.mod.orig || ! cmp -s go.sum /tmp/go.sum.orig; then
              git --no-pager diff -- go.mod go.sum; echo "go.mod/go.sum not tidy - run go mod tidy"; exit 1
            fi
          '''
          docker.image(env.GOLANGCI_IMAGE).inside("-e HOME=${env.WORKSPACE}/.home -e GOFLAGS=-buildvcs=false -e GOCACHE=${env.WORKSPACE}/.cache/go-build -e GOMODCACHE=${env.WORKSPACE}/.cache/gomod -e GOLANGCI_LINT_CACHE=${env.WORKSPACE}/.cache/golangci") {
            // Existing findings (29 at LINT_BASELINE, 2026-10-23) are reported and mark the build UNSTABLE;
            // anything new since LINT_BASELINE blocks. Move LINT_BASELINE forward as the backlog is fixed.
            catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE', message: 'Existing lint findings - see reports/golangci.xml') {
              sh 'golangci-lint run --timeout 5m --output.checkstyle.path reports/golangci.xml --output.text.path stdout'
            }
            sh 'git config --global --add safe.directory "$PWD"; golangci-lint run --timeout 5m --new-from-rev=${LINT_BASELINE}'
          }
        }
      }
    }

    // 1. Unit tests with the race detector + coverage gates: below COVERAGE_MIN fails, below COVERAGE_TARGET warns.
    stage('Unit tests') {
      steps {
        script {
          inGo """
            go test -race -count=1 -coverprofile=reports/coverage.out -covermode=atomic ./... 2>&1 | tee reports/go-test.txt
            go tool cover -html=reports/coverage.out -o reports/coverage.html
            go tool cover -func=reports/coverage.out | tail -1 | tee reports/coverage-total.txt
          """
          // the tee above hides go test's exit code: fail explicitly on any FAIL line
          if (sh(script: "grep -qE '^(FAIL|--- FAIL|panic:)' reports/go-test.txt", returnStatus: true) == 0) {
            error 'unit tests failed — see reports/go-test.txt'
          }
          def coverage = sh(script: "awk '/^total:/ { sub(\"%\",\"\",\$3); print \$3 }' reports/coverage-total.txt", returnStdout: true).trim()
          if (!coverage) {
            error 'no coverage total — see reports/go-test.txt'
          }
          // awk does the decimal comparison (exit 0 = below the limit)
          if (sh(script: "awk -v c=${coverage} -v l=${env.COVERAGE_MIN} 'BEGIN { exit !(c+0 < l+0) }'", returnStatus: true) == 0) {
            error "coverage ${coverage}% is below the ${env.COVERAGE_MIN}% minimum"
          }
          if (sh(script: "awk -v c=${coverage} -v l=${env.COVERAGE_TARGET} 'BEGIN { exit !(c+0 < l+0) }'", returnStatus: true) == 0) {
            unstable "coverage ${coverage}% is below the ${env.COVERAGE_TARGET}% target — see reports/coverage.html"
          } else {
            echo "coverage ${coverage}% meets the ${env.COVERAGE_TARGET}% target"
          }
        }
      }
    }

    // 5. SonarQube quality gate (optional until a server is configured).
    stage('Code quality (SonarQube)') {
      when { expression { return env.SONAR_ENABLED == 'true' } }
      steps {
        withSonarQubeEnv('sonarqube') {
          sh "sonar-scanner -Dsonar.projectVersion=${env.GIT_HASH}"
        }
        timeout(time: 10, unit: 'MINUTES') {
          waitForQualityGate abortPipeline: true
        }
      }
    }

    // 6 + 8 run in parallel: they only read the source tree (7, Secrets, ran first).
    stage('Security scans') {
      parallel {
        stage('SAST') {
          steps {
            catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE', message: 'SAST findings — see reports/semgrep.json') {
              script {
                docker.image(env.SEMGREP_IMAGE).inside("-e HOME=${env.WORKSPACE}/.home -e SEMGREP_SEND_METRICS=off") {
                  sh 'semgrep scan --config p/owasp-top-ten --config p/golang --exclude .cache --exclude .home --exclude ctx --exclude reports --json --output reports/semgrep.json --error --severity ERROR .'
                }
              }
            }
          }
        }
        stage('Dependencies (SCA)') {
          steps {
            // Vulnerabilities only: secrets are the Secrets stage, misconfigurations are Dockerfile / IaC.
            // Report first so it is archived even when the gate fails (as in dx-authz-go).
            sh 'trivy fs --scanners vuln --skip-dirs .cache,.home,ctx,reports --output reports/trivy-fs-report.txt .'
            catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE', message: 'Trivy: HIGH/CRITICAL vulnerable dependencies - see reports/trivy-fs-report.txt') {
              sh 'trivy fs --scanners vuln --skip-dirs .cache,.home,ctx,reports --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 .'
            }
          }
        }
      }
    }

    // 9. Third-party licenses of the Go modules (the license list Carbyne Stack attaches to its releases).
    // Trivy reads the licenses from the module cache Unit tests filled; GOPATH points it there.
    // CRITICAL = forbidden licenses (e.g. AGPL), HIGH = restricted (e.g. GPL): UNSTABLE until reviewed.
    stage('Licenses') {
      steps {
        sh 'mkdir -p .cache/gopath/pkg && ln -sfn "$PWD/.cache/gomod" .cache/gopath/pkg/mod'
        sh 'GOPATH="$PWD/.cache/gopath" trivy fs --scanners license --skip-dirs .cache,.home,ctx,reports --output reports/licenses.txt .'
        catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE', message: 'Restricted or forbidden licenses - see reports/licenses.txt') {
          sh 'GOPATH="$PWD/.cache/gopath" trivy fs --scanners license --skip-dirs .cache,.home,ctx,reports --severity HIGH,CRITICAL --exit-code 1 .'
        }
      }
    }

    // 10. Dockerfile and IaC misconfiguration.
    stage('Dockerfile / IaC') {
      steps {
        sh 'trivy config --skip-dirs .cache,.home,ctx,reports --severity HIGH,CRITICAL --exit-code 1 --output reports/trivy-config.txt . || { cat reports/trivy-config.txt; exit 1; }'
      }
    }

    stage('Build image') {
      steps {
        script {
          // <semver>-<short-sha>, per dx-gitops docs/CICD.md. Semver is the latest git tag, or 0.0.0 before
          // the first release. Never latest.
          SEMVER = sh(script: "git describe --tags --abbrev=0 2>/dev/null || echo 0.0.0", returnStdout: true).trim()
          env.IMAGE_TAG = "${SEMVER}-${env.GIT_HASH}"
          BUILD_TIME = sh(script: "date -u +%Y-%m-%dT%H:%M:%SZ", returnStdout: true).trim()
          env.BUILD_TIME = BUILD_TIME

          devImage = docker.build(
            "${IMAGE_REPO}:${env.IMAGE_TAG}",
            "--label org.opencontainers.image.source=https://github.com/datakaveri/p3dx_gov_layer " +
            "--label org.opencontainers.image.revision=${env.GIT_COMMIT} " +
            "--label org.opencontainers.image.version=${env.IMAGE_TAG} " +
            "--label org.opencontainers.image.created=${BUILD_TIME} ."
          )
        }
      }
    }

    // 11. Image scan with Trivy: OS/binary vulnerabilities plus the image config (root user, secrets in
    // ENV/labels, ...). CRITICAL blocks, HIGH warns (dx-gitops docs/CICD.md: fail on CRITICAL).
    stage('Image scan') {
      steps {
        script {
          def scan = "trivy image --image-config-scanners misconfig,secret"
          sh "${scan} --output reports/trivy-image-report.txt ${devImage.imageName()}"
          sh "${scan} --exit-code 1 --severity CRITICAL --ignore-unfixed ${devImage.imageName()}"
          catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE',
                     message: 'Trivy found fixable HIGH findings — see trivy-image-report.txt') {
            sh "${scan} --exit-code 1 --severity HIGH --ignore-unfixed ${devImage.imageName()}"
          }
        }
      }
    }

    stage('Push image') {
      when { expression { return isDeployBranch() } }
      steps {
        script {
          // A release is a vX.Y.Z git tag on the built commit: also publish the image as X.Y.Z.
          // (Polling watches the branch only, so tagging an already-built commit needs a manual "Build Now".)
          def release = sh(script: "git tag --points-at HEAD | grep -E '^v?[0-9]+\\.[0-9]+\\.[0-9]+\$' | sort -V | tail -1 | sed 's/^v//'", returnStdout: true).trim()
          docker.withRegistry(REGISTRY_URI, REGISTRY_CRED) {
            devImage.push(env.IMAGE_TAG)
            if (release) {
              devImage.push(release)
              echo "release ${release}: also pushed ${IMAGE_REPO}:${release}"
            }
          }
          // immutable reference used for signing / attestations
          env.IMAGE_DIGEST = sh(script: "docker inspect --format='{{index .RepoDigests 0}}' ${devImage.imageName()} | sed 's/.*@//'", returnStdout: true).trim()
          echo "pushed ${IMAGE_REPO}:${env.IMAGE_TAG}@${env.IMAGE_DIGEST}"
        }
      }
    }

    // 11. SBOM always; signature + SBOM/provenance attestations on published images.
    stage('Supply chain (SBOM, sign, provenance)') {
      steps {
        script {
          sh "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock ${env.SYFT_IMAGE} ${devImage.imageName()} -o cyclonedx-json > reports/sbom.cdx.json"
          if (isDeployBranch() && env.COSIGN_ENABLED == 'true') {
            writeFile file: 'reports/provenance.json', text: """{
  "buildDefinition": {
    "buildType": "https://jenkins.io/pipeline@v1",
    "externalParameters": {"repository": "https://github.com/datakaveri/p3dx_gov_layer", "ref": "${branchName()}"},
    "resolvedDependencies": [{"uri": "git+https://github.com/datakaveri/p3dx_gov_layer", "digest": {"gitCommit": "${env.GIT_COMMIT}"}}]
  },
  "runDetails": {
    "builder": {"id": "${env.JENKINS_URL}"},
    "metadata": {"invocationId": "${env.BUILD_URL}", "startedOn": "${env.BUILD_TIME}"}
  }
}
"""
            withCredentials([file(credentialsId: 'cosign-key', variable: 'COSIGN_KEY_FILE'),
                             string(credentialsId: 'cosign-password', variable: 'COSIGN_PASSWORD'),
                             usernamePassword(credentialsId: REGISTRY_CRED, usernameVariable: 'REG_USER', passwordVariable: 'REG_PASS')]) {
              sh '''
                set +x
                REF="$IMAGE_REPO@$IMAGE_DIGEST"
                run() { docker run --rm -e COSIGN_PASSWORD -v "$COSIGN_KEY_FILE:/keys/cosign.key:ro" -v "$PWD/reports:/reports:ro" \
                          -e REG_USER -e REG_PASS --entrypoint sh "$COSIGN_IMAGE" -c \
                          "cosign login ghcr.io -u \\"\\$REG_USER\\" -p \\"\\$REG_PASS\\" >/dev/null && $*"; }
                run cosign sign --yes --key /keys/cosign.key "$REF"
                run cosign attest --yes --key /keys/cosign.key --type cyclonedx --predicate /reports/sbom.cdx.json "$REF"
                run cosign attest --yes --key /keys/cosign.key --type slsaprovenance1 --predicate /reports/provenance.json "$REF"
              '''
            }
          } else {
            echo 'SBOM generated; signing skipped (not the deploy branch, or COSIGN_ENABLED=false)'
          }
        }
      }
    }

    // 12. Hand the tag to GitOps (only once dx-gitops has a values file for this service).
    stage('Bump dx-gitops dev') {
      when { expression { return isDeployBranch() && env.GITOPS_ENABLED == 'true' } }
      steps {
        // Username with password credential: the password must be a GitHub PAT.
        withCredentials([usernamePassword(credentialsId: GITOPS_CRED, usernameVariable: 'GH_USER', passwordVariable: 'GH_TOKEN')]) {
          script {
            def branch = "bot/${SERVICE}-${env.IMAGE_TAG}"
            // Token goes through the environment, never into the command line Jenkins echoes.
            sh """
              set +x
              set -e
              rm -rf gitops && mkdir gitops && cd gitops
              git init -q
              git remote add origin "https://x-access-token:\${GH_TOKEN}@github.com/${GITOPS_REPO}.git"
              git fetch -q --depth 1 origin ${GITOPS_BRANCH}
              git checkout -q -b ${branch} FETCH_HEAD

              f=environments/dev/${SERVICE}.yaml
              [ -f "\$f" ] || { echo "\$f does not exist in ${GITOPS_REPO}@${GITOPS_BRANCH}"; exit 1; }
              # Only the tag: directly under the top-level image: key.
              sed -i -E '/^image:/,/^[^ #]/ s|^  tag:.*|  tag: "${env.IMAGE_TAG}"|' "\$f"
              if ! grep -qE '^  tag: "${env.IMAGE_TAG}"' "\$f"; then
                echo "Could not set image.tag in \$f"
                exit 1
              fi
              git diff --stat

              git -c user.name='jenkins-ci' -c user.email='jenkins-ci@datakaveri.org' \\
                commit -q -am "chore(dev): ${SERVICE} -> ${env.IMAGE_TAG}"
              git push -q origin ${branch}
            """

            // Open the PR through the GitHub API (no gh CLI needed on the agent).
            sh """
              set +x
              curl -fsS -X POST \\
                -H "Authorization: Bearer \${GH_TOKEN}" \\
                -H "Accept: application/vnd.github+json" \\
                https://api.github.com/repos/${GITOPS_REPO}/pulls \\
                -d '{"title":"chore(dev): ${SERVICE} -> ${env.IMAGE_TAG}","head":"${branch}","base":"${GITOPS_BRANCH}","body":"Automated image bump from ${env.BUILD_URL}\\n\\nMerging deploys ${IMAGE_REPO}:${env.IMAGE_TAG} to dev via Argo CD."}'
            """
          }
        }
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
      // Don't let a long-lived agent fill up with old images.
      script {
        if (env.IMAGE_TAG) {
          sh "docker rmi ${IMAGE_REPO}:${env.IMAGE_TAG} || true"
        }
      }
    }
  }
}
