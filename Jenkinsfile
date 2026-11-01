@Library('homelab') _

// The registered job owns its source pin, lane, credentials and library revision.
def remotes = scm.userRemoteConfigs
def branches = scm.branches
def revision = params.SOURCE_SHA
if (remotes.size() != 1 || branches.size() != 1 ||
    remotes[0].url != 'https://github.com/rankupgames/wispkey.git' ||
    !(revision instanceof String) || !(revision ==~ /[0-9a-f]{40}/) ||
    !(branches[0].name in [revision, '${SOURCE_SHA}'])) {
    error('wispkey_ci_source_invalid')
}
def refspec = remotes[0].refspec
def prefix = '+refs/heads/'
def separator = ':refs/remotes/origin/'
if (!(refspec instanceof String) || !refspec.startsWith(prefix) || refspec.indexOf(separator) < 0) {
    error('wispkey_ci_refspec_invalid')
}
def branch = refspec.substring(prefix.length(), refspec.indexOf(separator))
if (!(branch ==~ /[A-Za-z0-9][A-Za-z0-9._\/-]{0,127}/) ||
    refspec != "${prefix}${branch}${separator}${branch}".toString()) {
    error('wispkey_ci_refspec_invalid')
}

// JOB_BASE_NAME selects one lane. Each lane runs its gates in order on the Linux worker.
// Timeouts match each lane's registered runTimeoutSeconds.
def laneTimeoutMinutes = [rust: 120, tray: 60, browser: 60, postgres: 60]
if (!laneTimeoutMinutes.containsKey(env.JOB_BASE_NAME)) {
    error('wispkey_ci_lane_unknown')
}
homelabPipeline(
    agentLabel: 'homelab-dev3-linux',
    branch: branch,
    sourceRepository: remotes[0].url,
    scmCredentialId: remotes[0].credentialsId,
    sourceRevisionParameter: 'SOURCE_SHA',
    scriptPath: 'Jenkinsfile',
    pipelineRevision: revision,
    timeoutMinutes: laneTimeoutMinutes[env.JOB_BASE_NAME],
    lanes: [
        rust: [os: 'linux', queueProfile: 'small-web', checkCommand: 'bash ci/jenkins/check.sh rust'],
        tray: [os: 'linux', queueProfile: 'small-web', checkCommand: 'bash ci/jenkins/check.sh tray'],
        browser: [os: 'linux', queueProfile: 'small-web', checkCommand: 'bash ci/jenkins/check.sh browser'],
        postgres: [os: 'linux', queueProfile: 'default-4', checkCommand: 'bash ci/jenkins/check.sh postgres'],
    ])
