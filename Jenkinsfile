// CI/CD for p3dx_gov_layer — check, build, scan, publish, deploy.
//
// On a build of DEPLOY_BRANCH this pipeline pushes ghcr.io/datakaveri/p3dx-gov-layer:<semver>-<sha> and, when
// DEPLOY_ENABLED, rolls that exact image (by digest) out to the dev cluster: deployment p3dx-gov-layer in
// namespace p3dx-auth-ui. If the rollout does not become ready it is rolled back and the build fails.
//
// Job type: plain Pipeline ("Pipeline script from SCM"), NOT Multibranch. Such a job has no BRANCH_NAME,
// only GIT_BRANCH (e.g. "origin/deploy_updates"), so the branch is derived from that. Branch Specifier: */deploy_updates.
// Other branches (e.g. main, version-0.1.0) run every check but do not push or deploy.
//
// The checks (see dx-azure-deployment/docs/cicd-pipeline-guide.html). One tool per job:
//   1 unit tests (-race, coverage gate, HTML coverage report)   2 compile + golangci-lint (incl. vet, gofmt)
//   3 go.mod guard (+ tidy)   4 commitlint + pre-commit   5 SonarQube quality gate   6 SAST (Semgrep)
//   7 secrets (gitleaks)   8 SCA (Trivy fs)   9 licenses (Trivy)   10 Dockerfile/IaC (Trivy config)
//   11 image scan (Trivy: vulnerabilities + image config)
//   12 push (+ X.Y.Z tag when the commit has a vX.Y.Z git tag)   13 deploy to the dev cluster (kubectl)
// Gates: blocking unless marked UNSTABLE below (security findings start UNSTABLE, as in dx-authz-go;
// tighten by removing the catchError once the backlog is cleared).
//
// Deploy: kubectl on the agent, authenticated as the agent pod's ServiceAccount (jenkins/jenkins-agent),
// which may only update the deployments in DEPLOY_TARGETS (dx-azure-deployment cicd/jenkins/deployer-rbac*.yaml).
// The cluster pulls the image with the ghcr-pull secret in DEPLOY_NAMESPACE.
//
// Agent needs only: docker, git, curl, trivy, kubectl. Every other tool runs from a pinned image.
//
// Jenkins credentials expected:
//   datakaveri-ghcr      username/password — push to ghcr.io (password = PAT with write:packages)
//   sonarqube            SonarQube server configured in Jenkins (Manage Jenkins > System), only if SONAR_ENABLED

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
    DEPLOY_ENABLED     = 'false'   // 'false': the running gov_layer is built with dx-azure-deployment build-time patches (TEE via
                                   // RabbitMQ, policy expiry, workload results) that are not in this repo yet;
                                   // deploying this image would remove them. 'true' once they are merged here.
    DEPLOY_NAMESPACE   = 'p3dx-auth-ui'
    DEPLOY_TARGETS     = 'p3dx-gov-layer/gov-layer'   // deployment/container, space separated
    DEPLOY_PULL_SECRET = 'ghcr-pull'   // docker-registry secret in DEPLOY_NAMESPACE (read:packages)
    DEPLOY_TIMEOUT     = '300s'   // per rollout; slower = rolled back
    GIT_HASH        = GIT_COMMIT.take(7)

    // Pinned tool images (bump deliberately, never :latest)
    GO_IMAGE        = 'golang:1.26-bookworm'       // matches go.mod / Dockerfile
    GOLANGCI_IMAGE  = 'golangci/golangci-lint:v2.14.0'   // v2: needs Go >= 1.26 support; config is .golangci.yml version 2
    LINT_BASELINE   = 'b0130a2256e233fecad283cadaddcd4a22092e3f'   // deploy_updates when CI was added; see Static checks
    NODE_IMAGE      = 'node:22-alpine'
    PRECOMMIT_IMAGE = 'python:3.12-bookworm'   // needs git (pre-commit); -slim has none
    SEMGREP_IMAGE   = 'semgrep/semgrep:1.140.0'
    GITLEAKS_IMAGE  = 'zricethezav/gitleaks:v8.28.0'

    // Gates and switches
    COVERAGE_MIN    = '80'      // % total statement coverage, blocking (26.5% on 2026-11-03: builds fail until tests reach it)
    SONAR_ENABLED   = 'false'   // 'true' once a SonarQube server is configured in Jenkins
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

    // 1. Unit tests with the race detector + coverage gate: below COVERAGE_MIN stops the build.
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
            error "coverage ${coverage}% is below the ${env.COVERAGE_MIN}% minimum — see reports/coverage.html"
          }
          echo "coverage ${coverage}% meets the ${env.COVERAGE_MIN}% minimum"
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
          env.IMAGE_DIGEST = sh(script: "docker inspect --format='{{index .RepoDigests 0}}' ${devImage.imageName()} | sed 's/.*@//'", returnStdout: true).trim()
          echo "pushed ${IMAGE_REPO}:${env.IMAGE_TAG}@${env.IMAGE_DIGEST}"
        }
      }
    }

    // 13. CD: roll the image just pushed (by digest, so the cluster runs exactly what was scanned) out to the
    // deployments in DEPLOY_TARGETS. kubectl patch is the equivalent of helm upgrade here: these services are
    // plain Deployments, not Helm releases. A rollout that is not ready within DEPLOY_TIMEOUT is undone
    // (all targets, back to the revision they had before this build) and the build fails.
    stage('Deploy (dev)') {
      when { expression { return isDeployBranch() && env.DEPLOY_ENABLED == 'true' && env.IMAGE_DIGEST } }
      steps {
        script {
          def image = "${IMAGE_REPO}@${env.IMAGE_DIGEST}"
          def k = "kubectl -n ${DEPLOY_NAMESPACE}"
          def targets = env.DEPLOY_TARGETS.tokenize(' ')
          def deployments = []
          def before = [:]
          for (t in targets) {
            def parts = t.tokenize('/')
            def d = parts[0]
            deployments << d
            before[d] = sh(script: "${k} get deployment/${d} -o jsonpath='{.metadata.annotations.deployment\\.kubernetes\\.io/revision}'", returnStdout: true).trim()
            def patch = groovy.json.JsonOutput.toJson([spec: [template: [spec: [
              imagePullSecrets: [[name: env.DEPLOY_PULL_SECRET]],
              containers: [[name: parts[1], image: image, imagePullPolicy: 'IfNotPresent']]]]]])
            // change-cause is copied to the new ReplicaSet: kubectl rollout history shows which build deployed what.
            sh "${k} annotate deployment/${d} kubernetes.io/change-cause='${env.JOB_NAME} #${env.BUILD_NUMBER} ${IMAGE_REPO}:${env.IMAGE_TAG}' --overwrite"
            sh "${k} patch deployment/${d} --type strategic -p '${patch}'"
          }
          def failed = []
          for (d in deployments) {
            if (sh(script: "${k} rollout status deployment/${d} --timeout=${DEPLOY_TIMEOUT}", returnStatus: true) != 0) {
              failed << d
            }
          }
          if (failed) {
            sh "${k} get pods -o wide || true"
            for (d in deployments) {
              def now = sh(script: "${k} get deployment/${d} -o jsonpath='{.metadata.annotations.deployment\\.kubernetes\\.io/revision}'", returnStdout: true).trim()
              if (now != before[d]) {
                sh "${k} rollout undo deployment/${d} --to-revision=${before[d]}"
                sh "${k} rollout status deployment/${d} --timeout=${DEPLOY_TIMEOUT} || true"
              }
            }
            error "deploy of ${image} failed for ${failed.join(', ')}: rolled back to the previous version"
          }
          sh "${k} get deployment ${deployments.join(' ')} -o wide"
          echo "deployed ${IMAGE_REPO}:${env.IMAGE_TAG} (${env.IMAGE_DIGEST}) to ${DEPLOY_NAMESPACE}: ${deployments.join(', ')}"
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
