#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from __future__ import print_function

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

import json
import re
import sys, traceback

import boto3

class AppErr(Exception):
	status = 500
	response = "Error"
	headers = {}
class AuthorizationMissing(AppErr):
	status = 401
	headers = {"WWW-Authenticate":"Basic realm=dyndns53"}
class HostnameException(AppErr):
	status = 404
	response = "nohost"
class AuthorizationException(AppErr):
	status = 403
	response = "badauth"
class FQDNException(AppErr):
	status = 400
	response = "notfqdn"
class BadAgentException(AppErr):
	status = 400
	response = "badagent"
class AbuseException(AppErr):
	status = 403
	response = "abuse"

client53 = boto3.client('route53','ca-central-1')

re_ip = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")

creds = {}
with open("creds.json", "r") as config_file:
	creds = json.load(config_file)

conf = {}
with open("config.json", "r") as config_file:
	conf = json.load(config_file)

def _parse_ip(ipstring):
	m = re_ip.match(ipstring)
	if bool(m) and all(map(lambda n: 0 <= int(n) <= 255, m.groups())):
		return ipstring
	else:
		raise BadAgentException("Invalid IP string: {}".format(ipstring))

def r53_upsert(host, hostconf, ip):

	record_type = hostconf['record']['type']

	record_set = client53.list_resource_record_sets(
		HostedZoneId=hostconf['zone_id'],
		StartRecordName=host,
		StartRecordType=record_type,
		MaxItems='1'
	)

	old_ip = None
	logger.info("Host={} for Zone:{} ".format(host, hostconf['zone_id']))
	if not record_set:
		msg = "No existing record found for host {} in zone {}"
		logger.info(msg.format(host, hostconf['zone_id']))
	else:
		logger.info(record_set)
		record = None

		if record_set and record_set['ResourceRecordSets'] and len(record_set['ResourceRecordSets']) > 0:
			record = record_set['ResourceRecordSets'][0]

		if record and record['Name'] == host and record['Type'] == record_type:
			if len(record['ResourceRecords']) == 1:
				for subrecord in record['ResourceRecords']:
					old_ip = subrecord['Value']
			else:
				msg = "Multiple existing records found for host {} in zone {}"
				raise ValueError(msg.format(host, hostconf['zone_id']))
		else:
			msg = "No existing record found for host {} in zone {}"
			logger.info(msg.format(host, hostconf['zone_id']))


	if old_ip == ip:
		logger.debug("Old IP same as new IP: {}".format(ip))
		return False

	logger.debug("Old IP was: {}".format(old_ip))
	return_status = client53.change_resource_record_sets(
		HostedZoneId=hostconf['zone_id'],
		ChangeBatch={
			'Changes': [
				{
					'Action': 'UPSERT',
					'ResourceRecordSet': {
						'Name': host,
						'Type': hostconf['record']['type'],
						'TTL':  hostconf['record']['ttl'],
						'ResourceRecords': [
							{
								'Value': ip
							}
						]
					}
				}
			]
		}
	)

	return return_status

def _handler(event, context):
	if 'headers' not in event or event['headers'] is None:
		msg = "Headers not populated properly. Check API Gateway configuration."
		raise AuthorizationMissing(msg)

	try:
		auth_header = event['headers']['Authorization']
	except KeyError as e:
		raise AuthorizationMissing("Authorization required but not provided.")

	try:
		auth_user, auth_pass = (
			auth_header[len('Basic '):].decode('base64').split(':') )
	except Exception as e:
		msg = "Malformed basicauth string: {}"
		raise BadAgentException(msg.format(event['headers']['Authorization']))

	if auth_user not in creds and auth_user not in conf:
		raise AuthorizationException("Bad username/password.")

	if creds[auth_user] != auth_pass:
		raise AuthorizationException("Bad username/password.")

	query = {}
	if 'queryStringParameters' in event:
		query = event['queryStringParameters']
	elif 'querystring' in event:
		query = event['querystring']

	try:
		logger.debug(query)
		hostname = query['hostname']
		hosts = set( h if h.endswith('.') else h+'.' for h in
				hostname.split(',') )
		logger.debug("Host supplied: {}".format(hosts))
	except KeyError as e:
		raise BadAgentException("Hostname(s) required but not provided.")

	if any(host not in conf[auth_user]['hosts'] for host in hosts):
		logger.info("Host: {} not found in config lookup(s)".format(conf[auth_user]['hosts']))
		raise HostnameException()

	try:
		ip = _parse_ip(query['myip'])
		logger.debug("User supplied IP address: {}".format(ip))
	except KeyError as e:
		ip = _parse_ip(event['requestContext']['identity']['sourceIp'])
		msg = "User omitted IP address, using best-guess from $context: {}"
		logger.info(msg.format(ip), exc_info=True)

	if any(r53_upsert(host,conf[auth_user]['hosts'][host],ip) for host in hosts):
		return "good {}".format(ip)
	else:
		return "nochg {}".format(ip)

def response_proxy(data, ctype="json"):
	logger.debug(data)
	response = {}
	response["isBase64Encoded"] = False
	response["statusCode"] = data["statusCode"]
	if "headers" in data:
		response["headers"] = data["headers"]
	else:
		response["headers"] = {}

	if "body" in data:
		if ctype == "json":
			response["headers"]["Content-Type"] = "teapplicationxt/json"
			response["body"] = json.dumps(data["body"])
		else:
			response["headers"]["Content-Type"] = "text/plain"
			response["body"] = data["body"]
	return response

def request_proxy(data):
	logger.debug(data)
	request = {}
	request = data
	if "body" in data and data["body"]:
		request["body"]=json.loads(data["body"])
	return request

def lambda_proxy_handler(event, context):
	response = {
		'headers': {},
		'body': {}
	}

	try:
		request = request_proxy(event)
		response["statusCode"]=200
		response["body"] = _handler(event, context)
	except Exception as e:
		logger.exception("Exception handling request")
		if isinstance(e, AppErr):
			response["statusCode"] = e.status
			response["headers"] = e.headers
			response["body"] = e.response
		else:
			response["statusCode"] = 500
			response["body"] = "{0}: {1}".format(e.__class__.__name__, e.message)
	return response_proxy(response, None)

def lambda_handler(event, context):
	response = _handler(event, context)
	return { 'status': 200, 'response': response }
