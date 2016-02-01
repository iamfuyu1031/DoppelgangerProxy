import string
import random
import fte.encoder
import regex2dfa
import os

def gen_random_string(length):
	chars=string.ascii_lowercase + string.digits
	return ''.join(random.choice(chars) for _ in range(length))

# Cut list into 16 chunks
def chunks(seq, size):
	newseq = []
	splitsize = 1.0/size*len(seq)
	for i in range(size):
		    newseq.append(seq[int(round(i*splitsize)):int(round((i+1)*splitsize))])
	return newseq

# Cut string into chunks
def cut_str_into_chunk(str1, chunk_size):
	if len(str1)%chunk_size == 0:
		chunk = [''] * (len(str1)/chunk_size)
	else:
		chunk = [''] * (len(str1)/chunk_size+1)
	for i in range(0, len(chunk)):
		try:
			chunk[i] = str1[chunk_size*i:chunk_size*(i+1)]
		except:
			chunk[i] = str1[chunk_size*i:len(str1)]
	return chunk

def convert_field_value_to_hex(value):
	tmp = value.split('+')
	output = ''
	for i in range(len(tmp)):
		output += hex(int(tmp[i]))[2:].zfill(2)
	return str(output)

def map_chunk_to_ntp_field(one_chunk, position, field):
	# Convert the one_chunk value to hex
	int_value = int(one_chunk,16)
	# Random pick a value from the group
	picked_value = random.choice(field[int_value])
	# Convert the picked value into hex format
	picked_hex = convert_field_value_to_hex(picked_value)
	return picked_hex

def map_fte_to_ntp(one_chunk, group, field):
	chunk = [''] * (len(group)-1)
	hex_output = ''
	for i in range(len(group)-1):
		chunk[i] = one_chunk[group[i]:group[i+1]]
		hex_output += map_chunk_to_ntp_field(chunk[i], i, field[i])
	return hex_output

def retrieve_long_field(long_byte_range, folder):
	bin_size = [1,1,3,4,2,4,4,4,4]
	working_dir = os.path.dirname(os.path.realpath(__file__))
	filename = [''] * (len(long_byte_range)-1)
	field = [[] for i in range(len(long_byte_range)-1)]
	for i in range(len(long_byte_range)-1):
		filename[i] = str(long_byte_range[i]) + '-' + str(long_byte_range[i+1])
		f = open(working_dir + '/' + folder + '/' + filename[i])
		line = f.readlines()
		f.close()
		data = [''] * len(line)
		for j in range(len(line)):
			data[j] = line[j].strip()
		field[i]+=chunks(data, 16 ** bin_size[i])
	return field

def retrieve_short_field(long_byte_range, folder):
	working_dir = os.path.dirname(os.path.realpath(__file__))
	filename = [''] * (len(long_byte_range)-1)
	field = [[] for i in range(len(long_byte_range)-1)]
	for i in range(len(long_byte_range)-1):
		filename[i] = str(long_byte_range[i]) + '-' + str(long_byte_range[i+1])
		f = open(working_dir + '/' + folder + '/' + filename[i])
		line = f.readlines()
		f.close()
		for j in range(len(line)):
			field[i].append(line[j].strip())
	return field	

def rewrite_output(output, folder, short_field):
	result = hex(int(random.choice(short_field[0])))[2:].zfill(2) + hex(int(random.choice(short_field[1])))[2:].zfill(2) + output
	return result

def add_padding_at_end(string, pad_char, size):
	result = string + pad_char * (size-len(string))
	return result

def pad_and_cut_packet(traffic_hex, size):
	if len(traffic_hex) < size:
		result = add_padding_at_end(traffic_hex, 'g', size)
	else:
		chunk = cut_str_into_chunk(traffic_hex, size)
		if len(chunk[len(chunk)-1]) < size:
			chunk[len(chunk)-1] = add_padding_at_end(chunk[len(chunk)-1], 'g', size)
		result = ''.join(chunk)
	new_chunk = cut_str_into_chunk(result, size)
	return new_chunk

def transform_string(input_string):
	# Initial parameters
	folder = 'ntp_packet_field_short_client'
	long_byte_range = [44,45,46,50,54,58,66,74,82,90]
	short_byte_range = [42,43,44]
	group = [0,1,2,5,9,11,15,19,23,27]
	length = 450
	regex = '^[0-9a-f]+$'
	# Encode as hex
	hex_string = input_string.encode('HEX')
	fixed_slice = 162 ## 27*6
	dfa = regex2dfa.regex2dfa(regex)
	fteObj = fte.encoder.DfaEncoder(dfa, fixed_slice)
	client_ciphertext = fteObj.encode(hex_string)

	# Read into all possible values for each field (only consider field with more than 16 observations)
	long_field = retrieve_long_field(long_byte_range, folder)
	short_field = retrieve_short_field(short_byte_range, folder)
	# Do original FTE
	dfa = regex2dfa.regex2dfa(regex)
	fteObj = fte.encoder.DfaEncoder(dfa, fixed_slice)
	client_ciphertext = fteObj.encode(hex_string)
	# Map to NTP traffic
	chunk =  cut_str_into_chunk(client_ciphertext,27)
	output = [''] * len(chunk)
	for i in range(len(chunk)):
		output[i] = rewrite_output(map_fte_to_ntp(chunk[i], group, long_field), folder, short_field)
	return output

if __name__ == '__main__':
	input_string = 'hello world'
	output = transform_string(input_string)
	print output

















