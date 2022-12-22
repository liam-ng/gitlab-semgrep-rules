require 'tmpdir'
require 'English'

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
      expect(@output).to match(%r{no match in /app}i)
    end

    describe 'exit code' do
      specify { expect(@exit_code).to be 0 }
    end
  end

  context 'with test project' do
    def parse_expected_report(expectation_name)
      path = File.join(expectations_dir, expectation_name, 'gl-sast-report.json')
      JSON.parse(File.read(path))
    end

    let(:global_vars) do
      {
        'ANALYZER_INDENT_REPORT': 'true',
        # CI_PROJECT_DIR is needed for `post-analyzers/scripts` to
        # properly resolve file locations
        # https://gitlab.com/gitlab-org/security-products/post-analyzers/scripts/-/blob/25479eae03e423cd67f2493f23d0c4f9789cdd0e/start.sh#L2
        'CI_PROJECT_DIR': '/app',
        'SECURE_LOG_LEVEL': 'debug',
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
        report_filename: 'gl-sast-report.json'
      )
    end

    let(:report) { scan.report }

    context 'with c' do
      let(:project) { 'c' }

      context 'by default' do
        it_behaves_like 'successful scan'

        describe 'created report' do
          it_behaves_like 'non-empty report'

          it_behaves_like 'recorded report' do
            let(:recorded_report) { parse_expected_report(project + '/default') }
          end

          it_behaves_like 'valid report'
        end
      end

      context 'when including primary_identifiers' do
        let(:variables) do
          { 'GITLAB_FEATURES': 'sast_fp_reduction' }
        end

        describe 'created report' do
          it_behaves_like 'non-empty report'

          it_behaves_like 'recorded report' do
            let(:recorded_report) do
              parse_expected_report('c/with-primary-identifiers')
            end
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

          it_behaves_like 'recorded report' do
            let(:recorded_report) { parse_expected_report(project) }
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

          it_behaves_like 'recorded report' do
            let(:recorded_report) do
              parse_expected_report('go/with-tracking')
            end
          end

          it_behaves_like 'valid report'
        end
      end

      context 'when using ruleset synthesis' do
        let(:project) { 'go/custom-ruleset-synthesis' }

        it_behaves_like 'successful scan'

        let(:variables) do
          { 'GITLAB_FEATURES': 'sast_custom_rulesets' }
        end

        describe 'created report' do
          it_behaves_like 'non-empty report'

          it_behaves_like 'recorded report' do
            let(:recorded_report) do
              parse_expected_report(project)
            end
          end

          it_behaves_like 'valid report'
        end
      end
    end

    context 'with java' do
      context 'when using maven build-tool on Java 11' do
        let(:project) { 'java/maven' }
        let(:variables) do
          {
            'SAST_JAVA_VERSION': 11,
            'MAVEN_CLI_OPTS': '-Dmaven.compiler.source=11 -Dmaven.compiler.target=11 -DskipTests --batch-mode'
          }
        end
        describe 'created report' do
          it_behaves_like 'non-empty report'
          it_behaves_like 'recorded report' do
            let(:recorded_report) do
              parse_expected_report(project)
            end
          end
          it_behaves_like 'valid report'
        end
      end

      context 'when using maven build-tool on Java 17' do
        let(:project) { 'java/maven' }
        let(:variables) do
          {
            'SAST_JAVA_VERSION': 17,
            'MAVEN_CLI_OPTS': '-Dmaven.compiler.source=17 -Dmaven.compiler.target=17 -DskipTests --batch-mode'
          }
        end
        describe 'created report' do
          it_behaves_like 'non-empty report'
          it_behaves_like 'recorded report' do
            let(:recorded_report) do
              parse_expected_report(project)
            end
          end
          it_behaves_like 'valid report'
        end
      end

      context 'when using gradle build-tool' do
        let(:project) { 'java/gradle' }
        describe 'created report' do
          it_behaves_like 'non-empty report'
          it_behaves_like 'recorded report' do
            let(:recorded_report) do
              parse_expected_report(project)
            end
          end
          it_behaves_like 'valid report'
        end
      end

      context 'when using maven build-tool for multimodules' do
        let(:project) { 'java/maven-multimodules' }
        describe 'created report' do
          it_behaves_like 'non-empty report'
          it_behaves_like 'recorded report' do
            let(:recorded_report) do
              parse_expected_report(project)
            end
          end
          it_behaves_like 'valid report'
        end
      end
    end

    context 'with scala' do
      context 'when using sbt' do
        let(:project) { 'scala/sbt' }
        let(:variables) do
          {
            'SAST_JAVA_VERSION': 17,
            'GITLAB_FEATURES': ''
          }
        end

        describe 'created report' do
          it_behaves_like 'non-empty report'
          it_behaves_like 'recorded report' do
            let(:recorded_report) { parse_expected_report(project) }
          end
          it_behaves_like 'valid report'
        end

        context 'when using sbt with primary identifiers' do
            let(:variables) do
              {
                'SAST_JAVA_VERSION': 17,
                'GITLAB_FEATURES': 'sast_fp_reduction'
              }
            end
    
            describe 'created report' do
              it_behaves_like 'non-empty report'
              it_behaves_like 'recorded report' do
                let(:recorded_report) { parse_expected_report('scala/sbt-with-primary-identifiers') }
              end
              it_behaves_like 'valid report'
            end
          end
      end

      
    end
  end
end
