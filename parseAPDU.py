import os, sys, requests, pickle
from bs4 import BeautifulSoup

SPACE = ' '
MAX_TAG_LEN = 8
ODA_READ_RECORD = []

DOL = ['9F38', '8C', '8D', '9F49', '9F69']
STRING_DECODABLE = ['50', '5F2D', '5F20']
BITS_DECODABLE = ['P1', 'P2', '95', '9F27', '9F45', '91', '8A', '9F0D',\
	'9F0E', '9F0F', '9F66', '9C', '9F6C', '82', '9F10', '9F71', '9F34', '9F07']

#you may add here the tags of atomic objs
ATOMS = STRING_DECODABLE + BITS_DECODABLE

def byte_to_bits(byte_val):
	s = ''
	l = []
	int_val = int('0x'+byte_val, 16) & 0xFF
	for i in range(8):
		if int_val & 1 > 0:
			l = ['b'+str(i+1)+'=1'] + l
			s = '1' + s
		else:
			l = ['b'+str(i+1)+'=0'] + l
			s = '0' + s
		int_val >>= 1
	#return byte_val + ' ' + s + ' (' +' '.join(l) + ')'
	return s

def bytes_to_bits(bytes):
	l = []
	for i in range(len(bytes)/2):
		l.append(byte_to_bits(bytes[2*i:2*i+2]))
	return ' '.join(l)

def decode(tag, data):
	decoded = ''
	#decode to string
	if tag in STRING_DECODABLE or (tag == '84' and len(data) == 28):
		decoded = data.decode('hex')
	#decode to bits
	elif tag in BITS_DECODABLE and data.strip('0') != '':
			decoded = bytes_to_bits(data)

	if decoded != '':
		decoded = '[=<decoded>"' + decoded + '"</decoded>]'
	return decoded

def html_line(s):
	return '<span><pre>' + s + '</pre></span>'

def build_read_record_commands(AFL): #AFL must be a string
	AFL = [int('0x'+AFL[2*i:2*(i+1)], 16) & 0xFF for i in range(len(AFL)/2)]
	commands = []
	i = 0
	while i < len(AFL):
		offline = AFL[i + 3]
		for j in range(AFL[i + 1], AFL[i + 2] + 1):
			cmd = "00B2"
			cmd += format(j, '#04X')[2:] #P1
			cmd += format(AFL[i] + 4, '#04X')[2:] #P2
			cmd += "00"
			if offline > 0:
				#print "  [info] The record in response to '" + cmd + "' is involved in ODA"
				ODA_READ_RECORD.append(cmd)
			offline -= 1 			
			commands.append(cmd)
		i += 4	
	return commands

def parse_DOL(dol, tags, tab):
	html = ''
	_dol = []
	while dol != '':
		l = min(MAX_TAG_LEN, len(dol)-2)
		while l > 0 and dol[:l] not in tags:
			l -= 2
		if l == 0:
			return html
		
		tag = dol[:l]
		tlen_hex = dol[l:l+2]
		dol = dol[l+2:]
		s = tab + '<tag>' + tag + '</tag>'\
						+ ' <len>' + tlen_hex + '</len>'
	
		tname = tags[tag][0]['Name']
		s += ' <comment_line>//' + tname + '</comment_line>'
		html += html_line(s)
		_dol.append((tag, tlen_hex, tname))
	
	return (html, _dol)

		
def build_APDU_commands():
	tags = {}

	#SELECT
	tags['00A4'] = {'Name': 'SELECT', 'P1': 'Reference control parameter (Table 41 p.128 Book 1)',\
									'P2': 'Selection options (Table 42 p. 128 Book 1)', 'Lc': '5-10',\
									'Data': 'File name', 'Le': '00'}
	
	#APPLICATION BLOCK
	tags['8C1E'] = {'Name': 'APPLICATION BLOCK', 'P1': '00', 'P2':'00',\
									'Lc': 'var.', 'Data': 'Message Authentication Code (MAC)',\
									'Le': 'Not present'}
	tags['841E'] = tags['8C1E']

	#APPLICATION UNBLOCK
	tags['8C18'] = {'Name': 'APPLICATION UNBLOCK', 'P1': '00', 'P2':'00',\
									'Lc': 'var.', 'Data': 'Message Authentication Code (MAC)',\
									'Le': 'Not present'}
	tags['8418'] = tags['8C18']

	#CARD BLOCK
	tags['8C16'] = {'Name': 'CARD BLOCK', 'P1': '00', 'P2':'00',\
									'Lc': 'var.', 'Data': 'MAC data component',\
									'Le': 'Not present'}
	tags['8416'] = tags['8C16']

	#EXTERNAL AUTHENTICATE
	tags['0082'] = {'Name': 'EXTERNAL AUTHENTICATE', 'P1': '00', 'P2':'00',\
								 	'Lc': '8-16', 'Data': 'Issuer Authentication Data (IAD)',\
									'Le': 'Not present'}
	#GENERATE AC
	tags['80AE'] = {'Name': 'GENERATE AC',\
									'P1': 'Reference control parameter (Table 12 p.55 Book 3)',\
									'P2':'00', 'Lc': 'var.', 'Data': 'Transaction-related data',\
									'Le': '00' }
	#GET CHALLENGE
	tags['0084'] = {'Name': 'GET CHALLENGE', 'P1': '00', 'P2':'00',\
									'Lc': 'Not present', 'Data': 'Not present', 'Le': '00'}
	
	#GET DATA
	tags['80CA'] = {'Name': 'GET DATA', 'P1': '9F',\
									'P2':['36', '13', '17', '4F'], 'Lc': 'Not present',\
									'Data': 'Not present', 'Le': '00'}
	
	#GET PROCESSSING OPTIONS
	tags['80A8'] = {'Name': 'GET PROCESSSING OPTIONS', 'P1': '00', 'P2':'00',\
									'Lc': 'var.', 'Data': 'PDOL data', 'Le': '00'}

	#INTERNAL AUTHENTICATE
	tags['0088'] = {'Name': 'INTERNAL AUTHENTICATE', 'P1': '00', 'P2':'00',\
									'Lc': 'var.', 'Data': 'Authentication-related data',\
									'Le':'00'}
	
	#PIN CHANGE/UNBLOCK
	tags['8C24'] = {'Name': 'PIN CHANGE/UNBLOCK', 'P1': '00', \
									'P2':['00', '01', '02'], 'Lc': 'var.', \
									'Data': 'Enciphered PIN data component, if present, \
									and MAC data component', 'Le': 'Not present'}
	tags['8424'] = tags['8C24']
	
	#READ RECORD
	tags['00B2'] = {'Name': 'READ RECORD', 'P1': 'Record number',\
									'P2': 'Reference control parameter (Table 21 p.65 Book 3)',\
									'Lc': 'Not present', 'Data': 'Not present', 'Le': '00'}

	#VERIFY
	tags['0020'] = {'Name': 'VERIFY', 'P1': '00',\
									'P2': 'Qualifier of the reference data (Table 23 p.68 Book 3)',\
									'Lc': 'var.', 'Data': 'Transaction PIN data',\
									'Le': 'Not present'}

	#COMPUTE CRYPTOGRAPHIC CHECKSUM
	tags['802A'] = {'Name': 'COMPUTE CRYPTOGRAPHIC CHECKSUM', 'P1': '8E',\
									'P2': '80',\
									'Lc': 'var.', 'Data': 'UDOL related data',\
									'Le': '00'}
	
	return tags

def download_APDU_tags(source):
	html = requests.get(source).content
	html = html.replace('</p>', '') #</p> within <td> tags cause problems
	parser = BeautifulSoup(html, 'html.parser')
	tables = [ parser.find('table') ]
	for table in tables:
		tags = {}
		th = [str(x.text.encode('utf-8')) for x in table.find_all('th')][1:]
		l = len(th)
		tds = [str(x.text.encode('utf-8')) for x in table.find_all('td') ]
		i=0
		while i < len(tds):
			tag = tds[i]
			if tag not in tags: tags[tag] = []
			d = {}
			tags[tds[i]].append(d)
			for j in range(l): d[ th[j] ] = tds[i+1+j]
			i += l + 1
	
	return tags

def parse_CAPDU(apdu, tags, dol):
	tag = apdu[:4]
	cmd = tags[tag]['Name']
	html = html_line('<tag>'+ tag + '</tag> <comment_line>//'+ cmd +'</comment_line>')
	tab = ' '*5
	o = 4
	for k in ['P1', 'P2']:
		pdata = apdu[o:o+2]
		pinfo = str(tags[tag][k])
		if pinfo == pdata:
			pinfo = k
		else:
			pinfo = k + ' - ' + pinfo
		html += html_line(tab + '<data>' + pdata\
						+ '</data> <comment_line>//' + pinfo
						+ ' ' + decode(k, pdata) + '</comment_line>')
		o += 2
	
	#if tags[tag]['Lc'] == 'Not present':
		#html += html_line('     <tag>Lc<tag> <comment_line>//Not present</comment_line>')
		#html += html_line('     <tag>Data<tag> <comment_line>//Not present</comment_line>')
	#else:
	if tags[tag]['Lc'] != 'Not present':
		lc_hex = apdu[8:10]
		lc = int('0x' + lc_hex, 16) & 0xFF
		#html += html_line(' '*5 + '<data>' + lc_hex + '</data> <comment_line>//Lc</comment_line>')

		#let's process the Data field now
		data = apdu[10 : 10+2*lc]
		s = tab + '<len>' + lc_hex + '</len> '
		
		if dol != [] and tag in ['80A8', '80AE', '0082']:
			html += html_line(s + '<comment_line>//' + str(tags[tag]['Data']) + '</comment_line>')
			tab1 = tab + ' '*3
			pos = 0
			tlen = int('0x'+data[2:4], 16) & 0xFF
			if tlen + 2 == lc:
				pos = 4
				html += html_line(tab1 + '<tag>'+ data[:2]+'<tag> <len>'\
								+ data[2:4] +'<len> <comment_line>//Command Template</comment_line>')
				tab1 += ' '*3
			i=0
			while pos < 2*lc and i < len(dol):
				(dtag, dtlen_hex, dtname) = dol[i]
				i += 1
				dtlen = int('0x'+dtlen_hex, 16) & 0xFF
				ddata = data[pos:pos+2*dtlen]
				#html += html_line(tab +	'<tag>' + dtag + '</tag> <len>'\
				#				+ dtlen_hex + '</len> <data>' + ddata\
				#				+ '</data> <comment_line>//' + dtname + '</comment_line>')
				html += html_line(tab1 +	'<data>' + ddata\
								+ '</data> <comment_line>//' + dtname + ' '
								+ decode(dtag, ddata) + '</comment_line>')
				pos += 2*dtlen

			del dol[:i]
			if pos < 2*lc:
				return html + '<p class=\"warning\">'\
										+ '[Warning] Couldn\'t extract full DOL from: '\
										+ data + ' (dol:'+ str(dol)\
										+', tlen:' + str(tlen) + ', lc:'+str(lc) +')</p>'
			'''if i < len(dol):
				return html + '<p class=\"warning\">'\
										+ '[Warning] Couldn\'t extract full DOL from: '\
										+ str(dol[i:]) + '</p>'
			'''
		else:
			ddata = ''
			if cmd == 'SELECT':
				ddata = decode('84', data)
			html += html_line(s + '<data>' + data + '</data> <comment_line>//'\
							+ str(tags[tag]['Data']) + ' ' + ddata + '</comment_line>')

	#if tags[tag]['Le'] == 'Not present':
		#html += html_line('     <tag>Le<tag> <comment_line>//Not present</comment_line>')
	#else:
	if tags[tag]['Le'] != 'Not present':
		html += html_line(tab + '<data>' + apdu[-2:] + '</data> <comment_line>//Le</comment_line>')
	return html
		
#recursive parser
def parse_RAPDU(apdu, tags, tab):
	l = min(MAX_TAG_LEN, len(apdu)-2)
	while l > 0:
		tag = apdu[:l]
		tlen_hex = apdu[l:l+2]
		tlen = int('0x'+tlen_hex, 16) & 0xFF
		#if tlen > 0 and l+2+2*tlen <= len(apdu) and tag in tags:
		if l+2+2*tlen <= len(apdu) and tag in tags:
			break
		l -= 2

	if l > 0:		
		tname = tags[tag][0]['Name']
		tdata = apdu[l+2:l+2+2*tlen]		
		#process the AFL to identify the records involved in ODA
		if tag == '94': build_read_record_commands(tdata)
		
		html_data = ''
		parse_in_depth = True
		if tag in DOL:
			parse_in_depth = False
			try:
				(html_sub, dol1) = parse_DOL(tdata, tags, tab + ' '*(l+1))				
			except:
				parse_in_depth = True

		if parse_in_depth:
			html_sub = ''
			b1 = False
			dol1 = []
			if tag not in ATOMS:
				(html_sub, b1, dol1) = parse_RAPDU(tdata, tags, tab + ' '*(l+1))		
			if not b1 and tlen > 0:
				html_data = ' <data>' + tdata + '</data>'
		
		html = html_line(tab + '<tag>' + tag + '</tag> <len>'+ tlen_hex\
						+ '</len>'+ html_data +' <comment_line>//'+ tname + ' '
						+ decode(tag, tdata) +'</comment_line>') + html_sub

		if l+2+2*tlen < len(apdu):
			(y, b2, dol2) = parse_RAPDU(apdu[l+2+2*tlen:], tags, tab)
			if y != '':
				return (html + y, True, dol1 + dol2)
		else: # if 2*tlen == len(apdu)-l-2:
			return (html, True, dol1)

	return ('', False, [])

def main():
	source = 'https://www.eftlab.com/knowledge-base/145-emv-nfc-tags/'
	apdu_file = sys.argv[1]
	html_file = sys.argv[2]

	CTAGS = build_APDU_commands()
	
	#get APDU tags from eftlab.com if not stored locally
	if not os.path.isfile('tags.pkl'):
		TAGS = download_APDU_tags(source)
		#further tags
		TAGS['9F0A'] = [{'Name': 'Application Selection Registered Proprietary Data (ASRPD)'}]
		TAGS['BF63'] = [{'Name': 'Unknown'}]
		TAGS['DF6F'] = [{'Name': 'Unknown'}]
		#possibly only for EMV contactless
		TAGS['7781'] = [{'Name': 'Response Message Template Format 2'}]
		TAGS['7081'] = [{'Name': 'READ RECORD Response Message Template'}]
		TAGS['9081'] = [{'Name': 'Issuer Public Key Certificate'}]
		TAGS['9F4B81'] = [{'Name': 'Signed Dynamic Application Data (SDAD)'}]
		TAGS['9F4681'] = [{'Name': 'Integrated Circuit Card (ICC) Public Key Certificate'}]
		output = open('tags.pkl', 'wb')
		pickle.dump(TAGS, output)
		output.close()
	else:
		input = open('tags.pkl', 'rb')
		TAGS = pickle.load(input)
		input.close()

	'''#write java code for Android app	
	for (tag, dict) in CTAGS.iteritems():
		#print 'CAPDU_TAGS.add(' + '\"' + tag + '\");'
		print 'map = new TreeMap<>();'
		for (k, v) in dict.iteritems():
			print 'map.put("' + k + '", "' + str(v) + '");'
		print 'CAPDU_TAGS.put(' + '"' + tag + '", map);'
		print
	
	for (tag, list) in TAGS.iteritems():
		name = list[0]['Name']
		#print 'APDU_TAGS.add(' + '"' + tag + '");'
		print 'APDU_TAGS.put(' + '"' + tag + '", "' + name.replace('\'','\\\'').replace('"','\\"').replace('\n', ' ')+'");'
	'''

	html = '<!DOCTYPE html><html><head><style>\
		body, p, pre, div {font-family: Consolas, "courier new";\
			color: #404040; font-size: 12px; line-height:.65em;}\
		tag {color: red}\
		len {color: green}\
		name {color: blue}\
		data {color: #8B4513}\
		.warning {color: #FF9966}\
		.comment_block {opacity: 0.5}\
		decoded {color: darkslategray; font-style: italic;}\
		comment_line {color: gray}\
		</style></head><body>'

	dol = [[],[]]
	lines = open(apdu_file).readlines()

	for i in range(len(lines)):
		line = lines[i].strip()

		comment = 0
		if line.startswith('//'):
			line = line.strip('//')
			comment = 1
			html += '<div class="comment_block">/*'

		if line.startswith('[C-APDU] '):
			cmd = line.split('[C-APDU] ', 1)[1]
			#reset dols
			if cmd == '00A404000E325041592E5359532E444446303100': dol = [[],[]]			
			html += html_line(line) + parse_CAPDU(cmd, CTAGS, dol[comment])
			
		elif line.startswith('[R-APDU] '):
			resp = line.split('[R-APDU] ', 1)[1]			
			html += html_line(line)
			
			(x, b, _dol) = parse_RAPDU(resp[:-4], TAGS, '')
			#if _dol != []: dol = _dol
			
			dol[1-comment] += _dol			
			if not lines[i-1].startswith('//[R-APDU] '):
				dol[comment] += _dol	 
			
			x += html_line('<data>' + resp[-4:] + '</data>')			
			if cmd in ODA_READ_RECORD:
				x = x.replace('<span>', html_line('<comment_line>//records included in ODA</comment_line>')
						+ '<span>', 1)			
			html += x
		
		else:
			html += html_line(line.replace('//', '<comment_line>//', 1) + '</comment_line>')

		if comment == 1: html += html_line('*/</div>')

	html += '</body></html>'

	f = open(html_file, 'w')
	f.write(html)
	f.close()
		
main()
