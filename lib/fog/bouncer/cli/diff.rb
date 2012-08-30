module Fog
  module Bouncer
    module CLI
      class DiffCommand < AbstractCommand
        option ["--diff-format"], "DIFF_FORMAT", "The diff output format (ec2)", :default => :ec2
        option ["--apply"], :flag, "Apply the differences"

        def execute
          doorlist = Fog::Bouncer.load(file)
          doorlist.import_remote_groups
          groups = doorlist.groups

          Fog::Bouncer::CLI::Diff.for(doorlist, diff_format)

          if apply? && confirm
            doorlist.sync
          end
        end
      end

      class Diff
        class EC2
          attr_reader :doorlist

          def self.diff(doorlist)
            new(doorlist).diff
          end

          def initialize(doorlist)
            @doorlist = doorlist
          end

          def diff
            @doorlist.groups.each do |group|
              if group.local? && !group.remote?
                puts "ec2-create-group #{group.name} -d '#{group.description}'"
              end

              group.sources.each do |source|
                source.protocols.each do |protocol|
                  if protocol.local? && !protocol.remote?
                    puts command(protocol, :authorize)
                  elsif !protocol.local? && protocol.remote?
                    puts command(protocol, :revoke)
                  end
                end
              end

              if group.remote? && !group.local?
                puts "ec2-delete-group #{group.name}"
              end
            end
          end

          private

          def command(protocol, action)
            cmd = "ec2-#{action} #{protocol.group.name} -P #{protocol.type}"
            source = protocol.source

            if protocol.type == "icmp"
              cmd << " -t #{protocol.from}:#{protocol.to}"
            else
              cmd << " -p #{protocol.from}-#{protocol.to}"
            end

            if source.is_a?(Fog::Bouncer::Sources::CIDR)
              cmd << " -s #{source.range}"
            else
              cmd << " -u #{source.user_id} -o #{source.name}"
            end

            cmd
          end
        end

        FORMATS = {
          :ec2 => Fog::Bouncer::CLI::Diff::EC2
        }

        def self.for(doorlist, diff_format)
          FORMATS[diff_format.to_sym].diff(doorlist)
        end
      end
    end
  end
end
