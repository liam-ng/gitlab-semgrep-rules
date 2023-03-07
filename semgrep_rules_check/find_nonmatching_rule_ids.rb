#! /bin/sh ruby

require "yaml"

# Some rules need to be refined and currently exceptional
RULE_ID_EXCLUSIONS = [
  "find_sec_bugs.PATH_TRAVERSAL_OUT-1.PATH_TRAVERSAL_OUT-1",
  "generic_error_disclosure",
  "node_error_disclosure",
]
YAML_FILE = ARGV[0]
raise "no file provided" unless YAML_FILE

def print_nonmatching_rules(rules, fatal=true)
  log_level = fatal ? "ERROR" : "WARN"

  if rules.any?
    puts
    puts "[#{log_level}] YAML validation failed for #{YAML_FILE}"
    puts "[#{log_level}] noncompliant rules:"
    rules.each do |rule|
      puts "  id: #{rule['id']}"
      puts "  primary_identifier: #{rule.dig('metadata', 'primary_identifier')}"
      puts "  secondary_identifier_count: #{rule.dig('metadata', 'secondary_identifiers')&.count}"
      puts "---" if rules.length > 1
    end

    exit(1) if fatal
  end
end

nonmatching_rules = YAML.load_file(YAML_FILE)["rules"].filter do |rule|
  id = rule.dig("id")
  primary_identifier = rule.dig("metadata", "primary_identifier")
  secondary_identifiers = rule.dig("metadata", "secondary_identifiers")
  # drop the first which corresponds to identifier type
  expected_secondary_identifiers_count = id.split('.').length-1

  id != primary_identifier ||
    secondary_identifiers.length != expected_secondary_identifiers_count
end

nonmatching_rules_with_exclusions, nonmatching_rules = nonmatching_rules.partition do |rule|
  RULE_ID_EXCLUSIONS.include? rule.dig("id")
end

print_nonmatching_rules(nonmatching_rules_with_exclusions, fatal=false)

print_nonmatching_rules(nonmatching_rules, fatal=true)
