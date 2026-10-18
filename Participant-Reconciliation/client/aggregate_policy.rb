#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "json"
require "yaml"

module TACVMPolicy
  SECTIONS = %w[
    roles workload_cvms artifacts secret_release communications lifecycle
  ].freeze

  class PolicyError < StandardError
    attr_reader :code, :details

    def initialize(code, message, details = {})
      super(message)
      @code = code
      @details = details
    end

    def to_h
      { "status" => "REJECTED", "error_code" => code,
        "message" => message, "details" => details }
    end
  end

  module Canonical
    module_function

    # Test encoding only. The production protocol still needs a frozen canonical
    # wire format. Hash keys are sorted and array order is preserved.
    def normalize(value)
      case value
      when Hash
        value.keys.map(&:to_s).sort.to_h do |key|
          original_key = value.key?(key) ? key : value.keys.find { |k| k.to_s == key }
          [key, normalize(value.fetch(original_key))]
        end
      when Array
        value.map { |item| normalize(item) }
      else
        value
      end
    end

    def json(value)
      JSON.generate(normalize(value))
    end

    def digest(value)
      "sha384:#{Digest::SHA384.hexdigest(json(value))}"
    end
  end

  class Aggregator
    SET_FIELDS = {
      "workload_cvms" => %w[mrtd_allowed rootfs_allowed accepted_tcb_statuses],
      "artifacts" => %w[digests registrars],
      "communications" => %w[endpoints]
    }.freeze

    REQUIREMENT_FIELDS = %w[
      require_launch_context require_trusted_service_channel_binding
    ].freeze

    ENCRYPTION_STRENGTH = {
      "OPTIONAL" => 0,
      "PREFERRED" => 1,
      "REQUIRED" => 2
    }.freeze

    attr_reader :document, :proposals, :context, :roster_slots

    def initialize(document)
      @document = stringify_keys(document)
      @context = @document.fetch("shared_context") do
        raise PolicyError.new("REJECT_CONTEXT", "shared_context is required")
      end
      @proposals = @document.fetch("proposals") do
        raise PolicyError.new("REJECT_PROPOSALS", "proposals are required")
      end
      raise PolicyError.new("REJECT_PROPOSALS", "proposals must be a list") unless @proposals.is_a?(Array)

      @roster_slots = derive_roster_slots
    end

    def aggregate
      validate_fixture_schema!
      validate_contexts!
      validate_authors!
      validate_defaults!

      roles = join_roles
      candidate = {
        "status" => "SUCCESS",
        "context" => Canonical.normalize(context),
        "proposal_digests" => proposal_digests,
        "roles" => roles,
        "workload_cvms" => join_workload_cvms,
        "artifacts" => join_artifacts,
        "secret_release" => join_secret_release,
        "communications" => join_communications,
        "lifecycle" => join_lifecycle
      }
      validate_role_references!(candidate)
      candidate["candidate_digest"] = Canonical.digest(candidate)
      candidate
    end

    private

    def stringify_keys(value)
      case value
      when Hash
        value.each_with_object({}) do |(key, item), output|
          output[key.to_s] = stringify_keys(item)
        end
      when Array
        value.map { |item| stringify_keys(item) }
      else
        value
      end
    end

    def validate_fixture_schema!
      schema = document["fixture_schema"]
      return if schema == "tacvm-policy-join-fixture/v0.1"

      raise PolicyError.new(
        "REJECT_SCHEMA", "unsupported fixture schema", "schema" => schema
      )
    end

    def derive_roster_slots
      roles = document["shared_roles"]
      if roles.is_a?(Hash) && !roles.empty?
        roles.keys.sort
      elsif document["roster_slots"].is_a?(Array)
        document["roster_slots"].map(&:to_s).sort
      else
        proposals.map { |proposal| proposal["author"].to_s }.sort
      end
    end

    def validate_contexts!
      proposals.each do |proposal|
        proposal_context = proposal.fetch("context", context)
        next if Canonical.normalize(proposal_context) == Canonical.normalize(context)

        raise PolicyError.new(
          "REJECT_CONTEXT", "proposal context does not match the active round",
          "author" => proposal["author"]
        )
      end
    end

    def validate_authors!
      authors = proposals.map { |proposal| proposal["author"].to_s }
      duplicates = authors.group_by(&:itself).select { |_slot, values| values.length > 1 }.keys
      unless duplicates.empty?
        raise PolicyError.new(
          "REJECT_DUPLICATE_AUTHOR", "more than one proposal for a roster slot",
          "slots" => duplicates.sort
        )
      end

      missing = roster_slots - authors
      unexpected = authors - roster_slots
      return if missing.empty? && unexpected.empty?

      raise PolicyError.new(
        "REJECT_INCOMPLETE_ROSTER", "proposal authors do not match the roster",
        "missing" => missing.sort, "unexpected" => unexpected.sort
      )
    end

    def validate_defaults!
      proposals.each do |proposal|
        defaults = proposal["defaults"]
        unless defaults.is_a?(Hash)
          raise PolicyError.new(
            "REJECT_DEFAULT", "every proposal must declare defaults",
            "author" => proposal["author"]
          )
        end

        SECTIONS.each do |section|
          value = defaults[section]
          next if %w[ANY DENY].include?(value)

          raise PolicyError.new(
            "REJECT_DEFAULT", "default must be ANY or DENY",
            "author" => proposal["author"], "section" => section,
            "value" => value
          )
        end
      end
    end

    def join_roles
      joined = {}
      shared_roles = document.fetch("shared_roles", {})
      merge_roles!(joined, shared_roles, "shared_roles")

      proposals.each do |proposal|
        roles = proposal.fetch("roles", {})
        roles = roles.fetch("assignments", roles) if roles.is_a?(Hash)
        merge_roles!(joined, roles, proposal["author"])
      end
      joined.sort.to_h
    end

    def merge_roles!(joined, roles, source)
      return if roles.nil? || roles.empty?
      unless roles.is_a?(Hash)
        raise PolicyError.new("REJECT_ROLES", "roles must be a mapping", "source" => source)
      end

      roles.each do |slot, role|
        slot = slot.to_s
        role = role.to_s
        if joined.key?(slot) && joined[slot] != role
          raise PolicyError.new(
            "BOTTOM_ROLE_CONFLICT", "conflicting roles for one slot",
            "slot" => slot, "left" => joined[slot], "right" => role,
            "source" => source
          )
        end
        joined[slot] = role
      end
    end

    def proposal_digests
      proposals.sort_by { |proposal| proposal["author"] }.map do |proposal|
        body = proposal.reject { |key, _value| key == "authentication" }
        body = body.merge("context" => context) unless body.key?("context")
        { "slot" => proposal["author"], "digest" => Canonical.digest(body) }
      end
    end

    def object_names(section)
      proposals.flat_map do |proposal|
        value = proposal.fetch(section, {})
        value.is_a?(Hash) ? value.keys : []
      end.map(&:to_s).uniq.sort
    end

    def restrictions_for(section, object_name)
      proposals.map do |proposal|
        section_value = proposal.fetch(section, {})
        entry = section_value.is_a?(Hash) ? section_value[object_name] : nil
        next [proposal, entry] unless entry.nil?

        [proposal, proposal.fetch("defaults").fetch(section)]
      end
    end

    def active_entries(section, object_name, bottom_code)
      restrictions = restrictions_for(section, object_name)
      if restrictions.any? { |_proposal, entry| entry == "DENY" }
        raise PolicyError.new(
          bottom_code, "a DENY default makes the named object unsatisfiable",
          "section" => section, "object" => object_name
        )
      end
      restrictions.filter_map do |_proposal, entry|
        next if entry == "ANY"
        unless entry.is_a?(Hash)
          raise PolicyError.new(
            "REJECT_POLICY_TYPE", "policy entry must be a mapping",
            "section" => section, "object" => object_name
          )
        end
        entry
      end
    end

    def join_workload_cvms
      object_names("workload_cvms").to_h do |name|
        entries = active_entries(
          "workload_cvms", name, "BOTTOM_EMPTY_WORKLOAD_CVM_IDENTITY"
        )
        joined = join_supported_entry_fields("workload_cvms", name, entries)
        SET_FIELDS.fetch("workload_cvms").each do |field|
          next unless joined.key?(field) && joined[field].empty?
          raise PolicyError.new(
            "BOTTOM_EMPTY_WORKLOAD_CVM_IDENTITY",
            "Workload CVM allowlist intersection is empty",
            "workload_cvm" => name, "field" => field
          )
        end
        [name, joined]
      end
    end

    def join_artifacts
      object_names("artifacts").to_h do |name|
        entries = active_entries("artifacts", name, "BOTTOM_EMPTY_ARTIFACT_SET")
        joined = join_supported_entry_fields("artifacts", name, entries)
        %w[digests registrars].each do |field|
          next unless joined.key?(field) && joined[field].empty?
          raise PolicyError.new(
            "BOTTOM_EMPTY_ARTIFACT_SET", "artifact allowlist intersection is empty",
            "artifact" => name, "field" => field
          )
        end
        joined["encryption"] = strongest_encryption(entries) if entries.any? { |entry| entry.key?("encryption") }
        [name, joined]
      end
    end

    def join_communications
      object_names("communications").to_h do |name|
        restrictions = restrictions_for("communications", name)
        denied = restrictions.any? { |_proposal, entry| entry == "DENY" }
        entries = restrictions.filter_map do |_proposal, entry|
          next if %w[ANY DENY].include?(entry)
          entry
        end
        joined = join_supported_entry_fields("communications", name, entries)
        joined["endpoints"] = [] if denied
        [name, joined]
      end
    end

    def join_supported_entry_fields(section, object_name, entries)
      supported = case section
                  when "workload_cvms"
                    SET_FIELDS.fetch(section) + REQUIREMENT_FIELDS
                  when "artifacts"
                    SET_FIELDS.fetch(section) + %w[encryption kind]
                  when "communications"
                    SET_FIELDS.fetch(section) + %w[direction protocol peer_identity]
                  end

      unknown = entries.flat_map(&:keys).uniq - supported
      unless unknown.empty?
        raise PolicyError.new(
          "REJECT_UNSUPPORTED_FIELD", "unsupported policy field",
          "section" => section, "object" => object_name,
          "fields" => unknown.sort
        )
      end

      joined = {}
      SET_FIELDS.fetch(section, []).each do |field|
        values = entries.filter_map { |entry| entry[field] }
        joined[field] = intersect(values) unless values.empty?
      end

      if section == "workload_cvms"
        REQUIREMENT_FIELDS.each do |field|
          values = entries.filter_map { |entry| entry[field] }
          joined[field] = values.any?(true) unless values.empty?
        end
      end

      exact_fields = case section
                     when "artifacts" then %w[kind]
                     when "communications" then %w[direction protocol peer_identity]
                     else []
                     end
      exact_fields.each do |field|
        values = entries.filter_map { |entry| entry[field] }
        next if values.empty?
        normalized = values.map { |value| Canonical.json(value) }.uniq
        if normalized.length > 1
          raise PolicyError.new(
            "BOTTOM_FIELD_CONFLICT", "exact-value policy fields disagree",
            "section" => section, "object" => object_name, "field" => field
          )
        end
        joined[field] = Canonical.normalize(values.first)
      end
      joined
    end

    def strongest_encryption(entries)
      values = entries.filter_map { |entry| entry["encryption"] }
      unknown = values - ENCRYPTION_STRENGTH.keys
      unless unknown.empty?
        raise PolicyError.new(
          "REJECT_ENCRYPTION", "unsupported encryption requirement",
          "values" => unknown.uniq.sort
        )
      end
      values.max_by { |value| ENCRYPTION_STRENGTH.fetch(value) }
    end

    def join_secret_release
      object_names("secret_release").to_h do |name|
        restrictions = restrictions_for("secret_release", name)
        denied = restrictions.any? { |_proposal, entry| entry == "DENY" }
        entries = restrictions.filter_map do |_proposal, entry|
          next if %w[ANY DENY].include?(entry)
          unless entry.is_a?(Hash) && (entry.keys - ["all_of"]).empty?
            raise PolicyError.new(
              "REJECT_UNSUPPORTED_FIELD", "secret release supports only all_of",
              "secret" => name
            )
          end
          entry
        end
        conditions = entries.flat_map { |entry| entry.fetch("all_of", []) }
        conditions = conditions.uniq { |condition| Canonical.json(condition) }
        conditions.sort_by! { |condition| Canonical.json(condition) }
        value = { "all_of" => conditions.map { |condition| Canonical.normalize(condition) } }
        value["deny"] = true if denied
        [name, value]
      end
    end

    def join_lifecycle
      workloads = object_names("lifecycle")
      workloads.to_h do |workload|
        operations = proposals.flat_map do |proposal|
          proposal.dig("lifecycle", workload)&.keys || []
        end.uniq.sort

        joined_operations = operations.to_h do |operation|
          requesters = proposals.flat_map do |proposal|
            proposal.dig("lifecycle", workload, operation)&.keys || []
          end.uniq.sort

          joined_requesters = requesters.to_h do |requester|
            constraints = proposals.filter_map do |proposal|
              edges = proposal.dig("lifecycle", workload, operation, requester)
              next edges unless edges.nil?
              next nil if proposal.dig("defaults", "lifecycle") == "ANY"
              []
            end
            [requester, intersect(constraints)]
          end
          [operation, joined_requesters]
        end
        [workload, joined_operations]
      end
    end

    def intersect(values)
      return [] if values.empty?
      canonical_sets = values.map do |value|
        unless value.is_a?(Array)
          raise PolicyError.new("REJECT_POLICY_TYPE", "allowlist must be an array")
        end
        value.to_h { |item| [Canonical.json(item), Canonical.normalize(item)] }
      end
      common_keys = canonical_sets.map(&:keys).reduce { |left, right| left & right } || []
      common_keys.sort.map { |key| canonical_sets.first.fetch(key) }
    end

    def validate_role_references!(candidate)
      roles = candidate.fetch("roles").values.uniq
      references = []
      candidate.fetch("artifacts").each_value do |artifact|
        references.concat(artifact.fetch("registrars", []))
      end
      candidate.fetch("lifecycle").each_value do |operations|
        operations.each_value { |requesters| references.concat(requesters.keys) }
      end

      references.grep(/^role:/).each do |reference|
        role = reference.delete_prefix("role:")
        next if roles.include?(role)
        raise PolicyError.new(
          "BOTTOM_UNMAPPED_ROLE", "policy refers to an unmapped role",
          "role" => role
        )
      end
    end
  end

  class ConfirmationGate
    def self.activate(candidate, roster_slots, confirmations)
      expected_digest = candidate.fetch("candidate_digest")
      by_slot = {}
      confirmations.each do |confirmation|
        slot = confirmation.fetch("slot").to_s
        if by_slot.key?(slot)
          raise PolicyError.new(
            "REJECT_DUPLICATE_CONFIRMATION", "duplicate candidate confirmation",
            "slot" => slot
          )
        end
        by_slot[slot] = confirmation.fetch("candidate_digest")
      end

      missing = roster_slots.map(&:to_s).sort - by_slot.keys.sort
      unless missing.empty?
        raise PolicyError.new(
          "REJECT_INCOMPLETE_CONFIRMATIONS", "not every roster slot confirmed",
          "missing" => missing
        )
      end

      mismatched = by_slot.select { |_slot, digest| digest != expected_digest }.keys.sort
      unless mismatched.empty?
        raise PolicyError.new(
          "REJECT_CONFIRMATION_DIGEST", "confirmations bind different candidates",
          "slots" => mismatched
        )
      end

      { "status" => "ACTIVE", "candidate_digest" => expected_digest }
    end
  end

  module CLI
    module_function

    def run(argv)
      command = argv.shift
      input_path = argv.shift
      unless %w[join verify].include?(command) && input_path
        warn "Usage: ruby aggregate_policy.rb <join|verify> INPUT.yaml [OUTPUT.yaml]"
        return 64
      end

      document = YAML.safe_load(File.read(input_path), aliases: false)
      candidate = Aggregator.new(document).aggregate

      if command == "verify"
        verify_expected_join!(candidate, document.fetch("expected_join"))
        puts "OK #{candidate.fetch('candidate_digest')}"
        return 0
      end

      output = YAML.dump(candidate)
      output_path = argv.shift
      if output_path
        File.write(output_path, output)
      else
        puts output
      end
      0
    rescue Errno::ENOENT => error
      warn YAML.dump("status" => "REJECTED", "error_code" => "INPUT_NOT_FOUND",
                     "message" => error.message)
      66
    rescue Psych::Exception => error
      warn YAML.dump("status" => "REJECTED", "error_code" => "INVALID_YAML",
                     "message" => error.message)
      65
    rescue PolicyError => error
      warn YAML.dump(error.to_h)
      2
    end

    def verify_expected_join!(candidate, expected)
      expected = expected.transform_keys(&:to_s)
      expected.each do |key, value|
        actual = candidate[key]
        next if Canonical.normalize(actual) == Canonical.normalize(value)
        raise PolicyError.new(
          "FIXTURE_MISMATCH", "candidate differs from expected fixture",
          "field" => key, "expected" => value, "actual" => actual
        )
      end
    end
  end
end

exit TACVMPolicy::CLI.run(ARGV) if $PROGRAM_NAME == __FILE__
