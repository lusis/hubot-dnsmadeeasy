# Description
#   Creates a new DNS entry with DNS Made Easy
#
# Dependencies:
#   "dme2": "0.0.2"
#   "underscore": "^1.6.0"
#   "clark": "0.0.6"
#
# Configuration:
#   HUBOT_DME2_API_KEY
#   HUBOT_DME2_API_SECRET
#
# Commands:
#   hubot dns me domains - returns a list of domains in DME account
#   hubot dns me stats - returns a sparkline of query counts from DME
#   hubot dns me lookup <record> <domain name> - returns and results for <record> in <domain name>
#   hubot dns me create <hostname> <domain name> <address> <type> - creates a record in <domain name>
#   hubot dns me delete <domain name> <record id> - deletes the record with id <record id> from <domain name>
#   hubot dns me log (max|count) - returns (max|count) entries from the audit log
#   hubot dns me last <n> <action> - returns the last N results for <action> operations from the audit log
#   hubot dns me max results <n> - sets the allowed max results returned from audit log queries
#
# Notes:
#   <optional notes required for the script>
#
# Author:
#   <github username of the original script author>
_ = require('underscore')
inspect = require('util').inspect
crypto = require 'crypto'
clark = require('clark')

dns_cache = {}

save = (robot) ->
  robot.brain.data.dnsme_cache = dns_cache

module.exports = (robot) ->
  dme_base_url = "https://api.dnsmadeeasy.com/V2.0"
  default_ttl = 86400
  logger = robot.logger
  logger.debug(inspect robot.brain.data.dnsme_cache)
  robot.brain.on 'loaded', =>
    dns_cache = robot.brain.data.dnsme_cache or {}
    dns_cache.domains or= {}
    dns_cache.records or= {}
    dns_cache.audit or= []
    dns_cache.max_results or= 10
    logger.info("Loaded dnsme_cache from brain with #{if dns_cache.domains isnt {} then Object.keys(dns_cache.domains).length else 0} domains and #{Object.keys(dns_cache.records).length} records")
  auth =
    api_key: process.env.HUBOT_DME2_API_KEY
    secret_key: process.env.HUBOT_DME2_API_SECRET
  
  robot.respond /dns me domains/i, (msg) ->
    _checkEnv msg

    _listDomains msg, (err, data) ->
      if err
        msg.send "Got a problem talking to DME: ", inspect err
        return
      if JSON.stringify(data) == '{}'
        msg.send "Looks like you have no domains? That can't be right"
        return
      buff = []
      for d in data.data
        dns_cache.domains[d.name] = d
        buff.push "#{d.name} - #{d.id}"
      save(robot)
      msg.send buff.join("\n")

  robot.respond /dns me stats/i, (msg) ->
    _checkEnv msg

    _getUsage msg, (err, data) ->
      if err
        msg.send "Problem making API call: ", err
      if JSON.stringify(data) == '{}'
        msg.send "Looks like we have no usage data"
        return
      
      logger.debug("Data is: #{inspect data}")
      stats = []
      for d in data
        stats.push d.total
      logger.debug("Stats: #{stats.join(' ')}")
      msg.send(clark(stats))
      return

  robot.respond /dns me delete (.*) (.*)/i, (msg) ->
    domain = _sanitize msg.match[1]
    record_id = parseInt(_sanitize(msg.match[2]), 10)

    logger.info("Delete request for #{record_id} in #{domain} record from #{msg.message.user.name}")
    logger.debug("Keys #{Object.keys(msg.message.user).join(", ")}")
    if "roles" of msg.message.user and "dns_admin" in msg.message.user.roles
      is_authorized = true
    else
      is_authorized = false
      logger.error("User #{msg.message.user.name} is authorized? #{is_authorized}")
    unless is_authorized
      msg.send "#{msg.message.user.name} is not authorized for this operation"
      return

    _checkEnv msg, (err) ->
      if err
        msg.send("Missing env vars for DME")
        return

    _findIdForDomain msg, domain, (err, data) ->
      if err
        msg.send "Unable to find id for #{domain}. Rebuild cache with 'hubot dns me domains'"
        return
      else
        domain_id = data
        logger.debug(inspect data)
        #msg.send("Functionality disabled for now")
        #return
        current_record = null
        current_record_key = null
        logger.debug("Current cache: #{Object.keys(dns_cache.records).join(", ")}")
        for k in Object.keys(dns_cache.records)
          logger.debug("Inspecting #{k}")
          c = dns_cache.records[k]
          #logger.debug(inspect c)
          if 'details' of c and c.details.id == record_id
            current_record_key = k
            current_record = c
            k = ''
          else
            logger.debug("No match from #{c.details.name} (#{c.details.id})")
        unless current_record
          logger.error("Could not find a cached record for #{record_id}")
          msg.reply "Unable to find a cached record for #{record_id}. Cannot continue"
          return
        logger.info("Found record in cache: #{current_record.details.id} - #{current_record.details.value} - #{current_record.details.type}")
        _deleteRecord msg, domain_id, record_id, (err, data) ->
          if JSON.parse(err)
            msg.send "#{err}"
            return
          else if err
            logger.error(err)
            msg.reply "Unknown error from DME API. Check hubot logs"
            return
          else
            logger.info("Entry deleted: Adding audit entry")
            dns_cache.audit = [] unless 'audit' of dns_cache
            audit =
              action: 'DELETE'
              domain: parseInt(domain_id, 10)
              id: parseInt(current_record.details.id, 10)
              name: current_record.details.name
              type: current_record.details.type
              value: current_record.details.value
              previous_value: null
              user: msg.message.user.name
              timestamp: Math.round((new Date()).getTime() / 1000)
            logger.info("Audit data: #{JSON.stringify(audit)}")
            dns_cache.audit.push audit
            logger.info("Attempting to delete #{current_record_key} from cache")
            delete dns_cache.records[current_record_key]
            msg.reply("Deleted entry for #{current_record.details.name}")
            return

  robot.respond /dns me max results (\d+)/i, (msg) ->
    if "roles" of msg.message.user and "dns_admin" in msg.message.user.roles
      is_authorized = true
    else
      is_authorized = false
      logger.error("User #{msg.message.user.name} is authorized? #{is_authorized}")
    unless is_authorized
      msg.send "#{msg.message.user.name} is not authorized for this operation"
      return
    dns_cache.max_results = parseInt(msg.match[1], 10)
    msg.send "Setting max allowable results to #{msg.match[1]}"
    return

  robot.respond /dns me log (max|\d+)/i, (msg) ->
    num_records = msg.match[1]

    if dns_cache.audit.length == 0
      msg.send "No audit entries found =("
      return

    buff = ["\n"]
    if num_records == 'max'
      num_records = dns_cache.max_results

    sorted_data = (_(dns_cache.audit).sortBy (a) -> [a.timestamp]).reverse()
    for entry in _.take(sorted_data, num_records)
      buff.push "#{entry.action} | #{entry.domain} | #{entry.id} | #{entry.name} | #{entry.type} | #{entry.value} | #{entry.user} | #{_twd entry.timestamp} ago"
    msg.reply buff.join("\n")

  robot.respond /dns me last (\d+) (\w+)/i, (msg) ->
    num_records = parseInt(msg.match[1], 10)
    logger.debug("count = #{num_records}")
    action = msg.match[2].toUpperCase()
    logger.debug("action = #{action}")

    if dns_cache.audit.length == 0
      msg.send "No audit entries found =("
      return

    buff = ["\n"]
    if num_records > dns_cache.max_results
      buff.push "(#{num_records} is larger than max allowed. Only returning last #{dns_cache.max_results})"
      num_records = dns_cache.max_results
    sorted_data = (_(dns_cache.audit).sortBy (a) -> [a.timestamp]).reverse()
    logger.debug(inspect sorted_data)
    valid_entries = _.where(sorted_data, {action: action})

    if valid_entries.length == 0
      msg.reply("No entries found")
      return
   
    for entry in _.take(valid_entries, num_records)
      buff.push "#{entry.action} | #{entry.domain} | #{entry.id} | #{entry.name} | #{entry.type} | #{entry.value} | #{entry.user} | #{_twd entry.timestamp} ago"
    msg.reply buff.join("\n")

  robot.respond /dns me create (.*) (.*) (.*) (.*)/i, (msg) ->
    record = _sanitize msg.match[1]
    domain = _sanitize msg.match[2]
    addr = _sanitize msg.match[3]
    type = _sanitize msg.match[4]

    logger.info("Create request for #{record} in #{domain} with value #{addr} as #{type} record from #{msg.message.user.name}")
    logger.debug(inspect msg.message.user)
    if "roles" of msg.message.user and "dns_admin" in msg.message.user.roles
      is_authorized = true
    else
      is_authorized = false
      logger.error("User #{msg.message.user.name} is authorized? #{is_authorized}")
    unless is_authorized
      msg.send "#{msg.message.user.name} is not authorized for this operation"
      return

    _checkEnv msg, (err) ->
      if err
        msg.send("Missing env vars for DME")
        return

    _findIdForDomain msg, domain, (err, data) ->
      if err
        msg.send "Unable to find id for #{domain}. Rebuild cache with 'hubot dns me domains'"
        return
      else
        domain_id = data
        logger.debug("Got request: #{record} #{domain} #{addr} #{type}")
        #msg.reply("Functionality disabled for now")
        #return
        _addRecord msg, domain_id, record, type, addr, default_ttl, (err, data) ->
          if JSON.parse(err)
            msg.send "#{inspect err}"
            return
          else if err
            logger.error(err)
            msg.reply "Unknown error from DME API. Check hubot logs"
            return
          else
            id_key = "#{domain_id}_#{record}_#{addr}_#{type}"
            dns_cache.records[id_key] = {}
            dns_cache.audit = [] unless 'audit' of dns_cache
            audit =
              action: 'CREATE'
              domain: parseInt(domain_id, 10)
              id: parseInt(data.id, 10)
              name: data.name
              type: data.type
              value: data.value
              change: null
              user: msg.message.user.name
              timestamp: Math.round((new Date()).getTime() / 1000)
            logger.info("Audit data: #{JSON.stringify(audit)}")
            dns_cache.audit.push audit
            msg.reply("Created entry for #{data.name}. ID is #{data.id} and TTL is #{data.ttl}")
            return

  robot.respond /dns me lookup (.*) (.*$)/i, (msg) ->
    _checkEnv msg, (err) ->
      if err
        msg.send("Missing env vars for DME")
        return
    record = _sanitize(msg.match[1])
    domain = _sanitize(msg.match[2])

    logger.info("Lookup request for #{record} in #{domain}")
    _findIdForDomain msg, domain, (err, data) ->
      if err
        msg.send "Unable to find id for #{domain}. Rebuild cache with 'hubot dns me domains'"
        return
      else
        domain_id = data

        _getRecord msg, domain_id, record, (err, data) ->
          if err
            msg.send "Got a problem talking to DME: ", inspect err
          if JSON.stringify(data) == '{}'
            msg.send "looks like no matches"
            return
          matches = []
          for r in data.data
            if r.name == ''
              logger.debug("Name is missing for record #{r.value} of type #{r.type}. Replacing with domain")
              r.name = domain
            logger.debug("Found record: #{r.name}\t#{r.value}\t#{r.id}\t#{r.type}")
            id_key = "#{domain_id}_#{r.name}_#{r.value}_#{r.type}"
            dns_cache.records[id_key] =
              details: r
            valid_result = "^#{record}.*$"
            if "#{r.name}".match valid_result
              matches.push "#{r.name} | #{r.type} | #{r.value} | #{r.id}"
          save(robot)
          if matches.length > 0
            msg.send matches.join("\n")
            return
          else
            msg.send "No matches found =("
            return

  _checkEnv = (msg, cb) ->
    unless auth.api_key or auth.api_secret
      return cb(true)

  _findIdForDomain = (msg, domain, cb) ->
    logger.debug("Looking up id for domain #{domain}")
    if 'domains' of dns_cache and domain of dns_cache.domains and 'id' of dns_cache.domains[domain]
      logger.debug(Object.keys(dns_cache.domains).join(","))
      logger.debug("Found domain id for #{domain}")
      return cb(null, dns_cache.domains[domain].id)
    else
      logger.debug(Object.keys(dns_cache.domains).join(","))
      logger.debug("Unable to find domain id for #{domain}")
      return cb("Unable to find domain id")

  _getUsage = (msg, cb) ->
    return _dmeGet msg, '/usageApi/queriesApi/', cb

  _listDomains = (msg, cb) ->
    return _dmeGet msg, '/dns/managed/', cb

  _addRecord = (msg, id, name, type, addr, ttl, cb) ->
    data =
      name: name
      type: type
      value: addr
      ttl: ttl

    logger.debug(JSON.stringify(data))
    return _dmePost msg, "/dns/managed/#{id}/records", data, cb

  _deleteRecord = (msg, domain_id, record_id, cb) ->
    logger.debug("Got to delete request for record #{record_id} for domain #{domain_id}")
    return _dmeDelete msg, "/dns/managed/#{domain_id}/records/#{record_id}/", cb

  _getRecord = (msg, id, record, cb) ->
    all_records = _dmeGet msg, "/dns/managed/#{id}/records", cb
    logger.debug("Got back #{all_records.data.length} records")
    return all_records

  _dmeGet = (msg, resource, cb) ->
    logger.debug("Got a request for: ",resource)
    logger.debug("Req url is: ",dme_base_url + resource)
    logger.debug("Callback is: ", inspect cb)
    req = msg.http(dme_base_url + resource)
    logger.debug("Req: ", inspect req)
    h = _dmeAuth()
    logger.debug("Headers: ", inspect h)
    req.headers(h)
    req.get() (err, res, body) ->
      if err
        return cb err
      json_body = null
      switch res.statusCode
        when 200
          json_body = JSON.parse(body)
          return cb(null, json_body)
        else
          logger.error("Error from DME API: ", body)
          return cb(body)

  _dmePost = (msg, resource, data, cb) ->
    logger.debug("Got a request for: ", resource)
    logger.debug("Req url is ",dme_base_url + resource)
    logger.debug("Data is ", inspect data)
    req = msg.http(dme_base_url + resource)
    h = _dmeAuth()
    req.headers(h)
    req.post(JSON.stringify(data)) (err, res, body) ->
      if err
        return cb err['error']
      json_body = null
      switch res.statusCode
        when 201
          json_body = JSON.parse(body)
          return cb(null, json_body)
        else
          logger.error("Error from DME API: ", body)
          return cb(body)

  _dmeDelete = (msg, resource, cb) ->
    logger.debug("Got a request for: ", resource)
    logger.debug("Req url is ",dme_base_url + resource)
    req = msg.http(dme_base_url + resource)
    h = _dmeAuth()
    req.headers(h)
    req.delete() (err, res, body) ->
      if err
        return cb err['error']
      switch res.statusCode
        when 200
          return cb(null, true)
        else
          logger.error("Error from DME API: ", body)
          return cb(body, false)

  _dmeAuth = ->
    logger.debug("Request for auth headers")
    date = new Date().toGMTString()
    logger.debug("Date string is: ", date)
    headers = {}
    headers['x-dnsme-apiKey'] = auth.api_key
    headers['x-dnsme-requestDate'] = date
    headers['x-dnsme-hmac'] = crypto.createHmac('sha1', auth.secret_key).update(date).digest('hex')
    headers['Content-Type'] = 'application/json'
    logger.debug("Computed headers: ", inspect headers)
    return headers

  _sanitize = (string) ->
    if string.match(/^http/)
      logger.info("Found html in text. Cleaning up")
      return string.replace /.*?:\/\//g, ""
    else
      return string

  _twd = (time) ->
    date = new Date(time * 1e3)
    diff = ((+new Date - date.getTime()) / 1e3)
    ddiff = Math.floor(diff / 86400)
    d = date.getDate()
    m = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(" ")[date.getMonth()]
    y = date.getFullYear().toString().slice(2)
    return  if isNaN(ddiff) or ddiff < 0
    ddiff is 0 and (diff < 60 and Math.floor(diff) + "s" or diff < 3600 and Math.floor(diff / 60) + "m" or diff < 86400 and Math.floor(diff / 3600) + "h") or ddiff < 365 and d + " " + m or ddiff >= 365 and d + " " + m + " " + y
