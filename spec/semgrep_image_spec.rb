require "tmpdir"
require "English"
require 'fileutils'

require 'gitlab_secure/integration_test/docker_runner'
require 'gitlab_secure/integration_test/shared_examples/scan_shared_examples'
require 'gitlab_secure/integration_test/shared_examples/report_shared_examples'
require 'gitlab_secure/integration_test/spec_helper'


describe 'running image' do
  let(:fixtures_dir) { 'qa/fixtures' }
  let(:expectations_dir) { 'qa/expect' }

  def image_name
    ENV.fetch('TMP_IMAGE', 'semgrep:latest')
  end

  def privileged
    ENV.fetch('PRIVILEGED', 'true') == 'true'
  end

  context 'with no project' do
    before(:context) do
      @output = `docker run -t --rm -w /app #{image_name}`
      @exit_code = $CHILD_STATUS.to_i
    end

    it 'shows there is no match' do
      expect(@output).to match(/no match in \/app/i)
    end

    describe 'exit code' do
      specify { expect(@exit_code).to be 0 }
    end
  end

  # rubocop:disable RSpec/MultipleMemoizedHelpers
  context 'with test project' do

    # `successful job` is a shared example for grouping the operations
    # of running a successful scan and further validating the generated
    # report against the expected report
    shared_examples "successful job" do
      it_behaves_like "successful scan"
      describe "created report" do
        it_behaves_like "non-empty report"
        it_behaves_like "recorded report" do
          let(:recorded_report) { GitlabSecure::IntegrationTest::Comparable.parse_expected_report(project, expectations_dir) }
        end
        it_behaves_like "valid report"
      end
    end

    # def parse_expected_report(expectation_name, report_name = "gl-sast-report.json")
    #   path = File.join(expectations_dir, expectation_name, report_name)
    #   if ENV['REFRESH_EXPECTED'] == "true"
    #     # overwrite the expected JSON with the newly generated JSON
    #     FileUtils.cp(scan.report_path, File.expand_path(path))
    #   end
    #   JSON.parse(File.read(path))
    # end

    let(:global_vars) do
      {
        'ANALYZER_INDENT_REPORT': 'true',
        # CI_PROJECT_DIR is needed for `post-analyzers/scripts` to
        # properly resolve file locations
        # https://gitlab.com/gitlab-org/security-products/post-analyzers/scripts/-/blob/25479eae03e423cd67f2493f23d0c4f9789cdd0e/start.sh#L2
        'CI_PROJECT_DIR': '/app',
        'SECURE_LOG_LEVEL': 'debug',
        'SEARCH_IGNORED_DIRS': 'bundle, node_modules, vendor, tmp', # remove test, tests
        'SEARCH_MAX_DEPTH': 20
      }
    end

    let(:project) { 'any' }
    let(:variables) { {} }
    let(:command) { [] }
    let(:script) { nil }
    let(:offline) { false }
    let(:target_dir) { File.join(fixtures_dir, project) }

    let(:scan) do
      GitlabSecure::IntegrationTest::DockerRunner.run_with_cache(
        image_name, fixtures_dir, target_dir, @description,
        command: command,
        script: script,
        offline: offline,
        privileged: privileged,
        variables: global_vars.merge(variables),
        report_filename: 'gl-sast-report.json')
    end

    let(:report) { scan.report }

    context "with c" do
      let(:project) { "c" }
      let(:variables) do
        { 'GITLAB_FEATURES': 'vulnerability_finding_signatures' }
      end

      context 'by default' do
        it_behaves_like "successful scan"

        describe "created report" do
          it_behaves_like "non-empty report"

          it_behaves_like "recorded report" do
            let(:recorded_report) { GitlabSecure::IntegrationTest::Comparable.parse_expected_report(project + '/default', expectations_dir) }
          end

          it_behaves_like "valid report"
        end
      end

      context 'when including primary_identifiers' do
        let(:variables) do
          { 'GITLAB_FEATURES': 'vulnerability_finding_signatures,sast_fp_reduction' }
        end

        describe 'created report' do
          it_behaves_like 'non-empty report'

          it_behaves_like "recorded report" do
            let(:recorded_report) {
              GitlabSecure::IntegrationTest::Comparable.parse_expected_report('c/with-primary-identifiers', expectations_dir)
            }
          end

          it_behaves_like 'valid report'
        end
      end
    end

    context 'with go' do
      let(:project) { 'go/default' }

      context 'by default' do
        it_behaves_like 'successful scan'

        describe 'created report' do
          it_behaves_like 'non-empty report'

          it_behaves_like "recorded report" do
            let(:recorded_report) { GitlabSecure::IntegrationTest::Comparable.parse_expected_report(project, expectations_dir) }
          end

          it_behaves_like 'valid report'
        end
      end

      context 'when including tracking signatures' do
        let(:variables) do
          { 'GITLAB_FEATURES': 'vulnerability_finding_signatures' }
        end

        describe 'created report' do
          it_behaves_like 'non-empty report'

          it_behaves_like "recorded report" do
            let(:recorded_report) {
              GitlabSecure::IntegrationTest::Comparable.parse_expected_report('go/with-tracking', expectations_dir)
            }
          end

          it_behaves_like 'valid report'
        end
      end

      context 'when VET FP reduction for Go' do
        context 'feature is enabled' do
          let(:project) { 'go/fpreduction' }
          let(:variables) do
            {
              'GITLAB_FEATURES': 'vulnerability_finding_signatures,sast_fp_reduction',
              'CI_PROJECT_ROOT_NAMESPACE': 'gitlab-org'
            }
          end
          it_behaves_like 'successful scan'
          describe 'created report' do
            it_behaves_like 'non-empty report'
            it_behaves_like 'recorded report' do
              let(:recorded_report) {
                GitlabSecure::IntegrationTest::Comparable.parse_expected_report('go/with-fp-reduction', expectations_dir, 'gl-sast-report-ff-enabled.json')
              }
            end

            it_behaves_like 'valid report'
          end
        end

        context 'feature is disabled' do
          let(:project) { 'go/fpreduction' }
          let(:variables) do
            {
              'GITLAB_FEATURES': 'vulnerability_finding_signatures',
              'CI_PROJECT_ROOT_NAMESPACE': 'gitlab-org'
            }
          end

          it_behaves_like 'successful scan'
          describe 'created report' do
            it_behaves_like 'non-empty report'
            it_behaves_like 'recorded report' do
                let(:recorded_report) {
                  GitlabSecure::IntegrationTest::Comparable.parse_expected_report('go/with-fp-reduction', expectations_dir, 'gl-sast-report-ff-disabled.json')
                }
            end
            it_behaves_like 'valid report'
          end
        end

      end

      context 'when using ruleset synthesis' do
        let(:project) { 'go/custom-ruleset-synthesis' }

        it_behaves_like 'successful scan'

        let(:variables) do
          { 'GITLAB_FEATURES': 'vulnerability_finding_signatures, sast_custom_rulesets' }
        end

        describe 'created report' do
          it_behaves_like 'non-empty report'

          it_behaves_like "recorded report" do
            let(:recorded_report) {
              GitlabSecure::IntegrationTest::Comparable.parse_expected_report(project, expectations_dir)
            }
          end

          it_behaves_like 'valid report'
        end
      end
    end

    context "with java" do

      context 'when using maven build-tool on Java 11' do
        let(:project) { 'java/maven' }
        let(:variables) do
          {
            'SAST_JAVA_VERSION': 11,
            'MAVEN_CLI_OPTS': '-Dmaven.compiler.source=11 -Dmaven.compiler.target=11 -DskipTests --batch-mode',
            'GITLAB_FEATURES': 'vulnerability_finding_signatures'
          }
        end
        describe 'created report' do
          it_behaves_like 'non-empty report'
          it_behaves_like "recorded report" do
            let(:recorded_report) {
              GitlabSecure::IntegrationTest::Comparable.parse_expected_report(project, expectations_dir)
            }
          end
          it_behaves_like 'valid report'
        end
      end

      context 'when using maven build-tool on Java 17' do
        let(:project) { 'java/maven' }
        let(:variables) do
          {
            'SAST_JAVA_VERSION': 17,
            'MAVEN_CLI_OPTS': '-Dmaven.compiler.source=17 -Dmaven.compiler.target=17 -DskipTests --batch-mode',
            'GITLAB_FEATURES': 'vulnerability_finding_signatures'
          }
        end
        describe 'created report' do
          it_behaves_like 'non-empty report'
          it_behaves_like "recorded report" do
            let(:recorded_report) {
              GitlabSecure::IntegrationTest::Comparable.parse_expected_report(project, expectations_dir)
            }
          end
          it_behaves_like 'valid report'
        end
      end

      context 'when using gradle build-tool' do
        let(:project) { 'java/gradle' }
        let(:variables) do
          { 'GITLAB_FEATURES': 'vulnerability_finding_signatures' }
        end
        describe 'created report' do
          it_behaves_like 'non-empty report'
          it_behaves_like "recorded report" do
            let(:recorded_report) {
              GitlabSecure::IntegrationTest::Comparable.parse_expected_report(project, expectations_dir)
            }
          end
          it_behaves_like 'valid report'
        end
      end

      context 'when using maven build-tool for multimodules' do
        let(:project) { 'java/maven-multimodules' }
        let(:variables) do
          { 'GITLAB_FEATURES': 'vulnerability_finding_signatures' }
        end

        describe 'created report' do
          it_behaves_like 'non-empty report'
          it_behaves_like "recorded report" do
            let(:recorded_report) {
              GitlabSecure::IntegrationTest::Comparable.parse_expected_report(project, expectations_dir)
            }
          end
          it_behaves_like 'valid report'
        end
      end

    end

    context 'with python' do
      let(:variables) do
        { 'GITLAB_FEATURES': 'vulnerability_finding_signatures' }
      end

      context 'when using pip package management' do
        let(:project) { 'python/pip' }
        it_behaves_like 'successful job'
      end

      context 'when using pipenv package management' do
        let(:project) { 'python/pipenv' }
        it_behaves_like 'successful job'
      end

      context 'when using pip package management for flask-based python project', focus: true do
        let(:project) { 'python/pip-flask' }
        it_behaves_like 'successful job'
      end

      context 'when using multi-module python project' do
        let(:project) { 'python/pip-multi-project' }
        it_behaves_like 'successful job'
      end

      context 'when adding custom rulesets in the project' do
        let(:project) { 'python/pip-flask-custom-rulesets' }
        let(:variables) do
          { 'GITLAB_FEATURES': 'vulnerability_finding_signatures, sast_custom_rulesets' }
        end
        it_behaves_like 'successful job'
      end

      context 'when synthesizing rulesets in the project' do
        let(:project) { 'python/pip-flask-custom-rulesets-with-passthrough' }
        let(:variables) do
          { 'GITLAB_FEATURES': 'vulnerability_finding_signatures, sast_custom_rulesets' }
        end
        it_behaves_like 'successful job'
      end
    end

    context 'with javascript' do
      let(:variables) do
        { 'GITLAB_FEATURES': 'vulnerability_finding_signatures' }
      end

      context 'when including tracking signatures' do
        let(:project) { 'js/default' }
        let(:variables) do
          { 'GITLAB_FEATURES': 'vulnerability_finding_signatures' }
        end

        describe 'created report' do
          it_behaves_like 'non-empty report'

          it_behaves_like "recorded report" do
            let(:recorded_report) {
              GitlabSecure::IntegrationTest::Comparable.parse_expected_report('js/with-tracking', expectations_dir)
            }
          end

          it_behaves_like 'valid report'
        end
      end

      context 'when a project contains JS files' do
        let(:project) { 'js/default' }
        it_behaves_like 'successful job'
      end

      context 'when a project contains JSX files' do
        let(:project) { 'js/jsx' }
        it_behaves_like 'successful job'
      end

      context 'when a typescript project contains TSX files' do
        let(:project) { 'js/typescript-tsx' }
        it_behaves_like 'successful job'
      end

      context 'when a typescript project uses Yarn package management' do
        let(:project) { 'js/typescript-yarn' }
        it_behaves_like 'successful job'
      end

    end

    context 'with csharp' do
      let(:variables) do
        { 'GITLAB_FEATURES': 'vulnerability_finding_signatures' }
      end

      context '.NET Core-based project' do
        let(:project) { 'csharp/dotnetcore' }
        it_behaves_like 'successful job'
      end

      context '.NET Core-based projects under one solution container' do
        let(:project) { 'csharp/dotnetcore-multiproject' }
        it_behaves_like 'successful job'
      end

      context '.NET Core-based projects under different solution containers' do
        let(:project) { 'csharp/dotnetcore-multisolution' }
        it_behaves_like 'successful job'
      end

      context '.NET Core-based project using MSBuild build system' do
        let(:project) { 'csharp/dotnetcore-msbuild' }
        it_behaves_like 'successful job'
      end
    end

  end
end
