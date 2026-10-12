# Managed by Ansible (roles/gitlab). Create GitLab accounts for teammates.
# Run as root on mgmt-git01, feeding the roster on stdin (dry run first):
#   DRY_RUN=1 gitlab-rails runner /usr/local/sbin/gitlab-team-users.rb < roster.csv
#   gitlab-rails runner /usr/local/sbin/gitlab-team-users.rb < roster.csv
# Roster lines: username,Full Name,email[,role]   role: guest|reporter|developer|maintainer
# (default developer). Tab-separated lines (a spreadsheet paste) are accepted too.
# Lines starting with # are ignored.
# Every line is checked before anything is created; one bad line creates nothing.
# Missing users get a random temporary password that must be changed at first sign-in and
# are added to the group (default hpcc; GITLAB_TEAM_GROUP). Existing users and existing
# group members are left untouched (no role changes). Each temporary password is printed
# once, on the line right after its account is created.
require 'securerandom'
STDOUT.sync = true
dry_run = ENV['DRY_RUN'] == '1'
group = Group.find_by_full_path(ENV.fetch('GITLAB_TEAM_GROUP', 'hpcc')) or abort('group not found')
admin = User.find_by_username('root') or abort('root user not found')
org_id = Organizations::Organization.default_organization.id
roles = { 'guest' => Gitlab::Access::GUEST, 'reporter' => Gitlab::Access::REPORTER,
          'developer' => Gitlab::Access::DEVELOPER, 'maintainer' => Gitlab::Access::MAINTAINER }

# Pass 1: parse and validate every line.
entries = []
errors = []
STDIN.each_line.with_index(1) do |raw, n|
  line = raw.sub(/\A﻿/, '').strip
  next if line.empty? || line.start_with?('#')
  sep = if line.include?("\t") then "\t"   # spreadsheet paste; cells never hold tabs
        elsif line.include?(',') then ','
        end
  unless sep
    errors << "line #{n}: no comma or tab between fields (spaces are not a separator)"
    next
  end
  fields = line.split(sep).map(&:strip)
  if fields.size < 3 || fields.size > 4
    errors << "line #{n}: #{fields.size} fields; expected username,Full Name,email[,role]"
    next
  end
  username, name, email, role = fields
  role = role.to_s.empty? ? 'developer' : role.downcase
  errors << "line #{n}: username '#{username}' is not valid" unless username.match?(/\A[A-Za-z0-9][A-Za-z0-9._-]*\z/)
  errors << "line #{n}: full name is empty" if name.empty?
  errors << "line #{n}: email is not valid" unless email.match?(/\A[^@\s]+@[^@\s]+\.[^@\s]+\z/)
  errors << "line #{n}: unknown role '#{role}'" unless roles.key?(role)
  errors << "line #{n}: #{username} appears more than once" if entries.any? { |e| e[:username].casecmp?(username) }
  entries << { n: n, username: username, name: name, email: email, role: role }
end
unless errors.empty?
  puts "Roster rejected; nothing was created:"
  errors.each { |e| puts "  #{e}" }
  exit 1
end

# Pass 2: create missing users (or report what would happen).
puts(dry_run ? "DRY RUN: nothing will be created" : "Temporary passwords are shown once; hand them over privately. Each must be changed at first sign-in.")
entries.each do |e|
  user = User.find_by_username(e[:username])
  member = user && group.members.find_by(user_id: user.id)
  if member
    puts "  line #{e[:n]}: #{e[:username].ljust(20)} exists, already #{member.human_access} in #{group.full_path} (untouched)"
    next
  end
  if dry_run
    action = user ? "exists; would be added as #{e[:role]}" : "would be created and added as #{e[:role]}"
    puts "  line #{e[:n]}: #{e[:username].ljust(20)} #{action} (#{e[:name]})"
    next
  end
  unless user
    temp = "#{SecureRandom.alphanumeric(10)}-#{SecureRandom.alphanumeric(10)}"
    res = Users::CreateService.new(admin, username: e[:username], name: e[:name], email: e[:email],
            password: temp, password_expires_at: Time.current, skip_confirmation: true,
            organization_id: org_id).execute
    user = res.respond_to?(:payload) ? res.payload[:user] : res
    unless user&.persisted?
      msg = res.respond_to?(:message) ? res.message : user&.errors&.full_messages&.join('; ')
      abort("line #{e[:n]}: create #{e[:username]} failed: #{msg} (accounts listed above were created)")
    end
    puts "  line #{e[:n]}: #{e[:username].ljust(20)} created   temporary password: #{temp}"
  end
  group.add_member(user, roles[e[:role]], current_user: admin)
  puts "  line #{e[:n]}: #{e[:username].ljust(20)} is #{group.members.find_by(user_id: user.id)&.human_access} in #{group.full_path}"
end
