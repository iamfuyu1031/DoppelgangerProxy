import string
import random
import fte.encoder
import regex2dfa
import xml.etree.ElementTree as ET
import os

# Symbol --> Group
# a --> timing < 0.025, size < 10
# b --> timing < 0.025, size: 10-20
# c --> timing < 0.025, size: 20-35
# d --> timing < 0.025, size: 35-53
# e --> timing < 0.025, size: 53-65
# f --> timing < 0.025, size: > 65
# g --> timing > 0.025, size < 10
# h --> timing > 0.025, size: 10-20
# i --> timing > 0.025, size: 20-35
# j --> timing > 0.025, size: 35-53
# k --> timing > 0.025, size: 53-65
# l --> timing > 0.025, size: > 65
def gen_random_string(length):
	chars=string.ascii_lowercase + string.digits
	return ''.join(random.choice(chars) for _ in range(length))

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


def read_hmm(filename, start, one_seed):
	random.seed(one_seed)
	tree = ET.parse(filename)
	root = tree.getroot()
	# Get all states and transitions
	state = []
	for child in root:
		for gdchild in child:
			if gdchild.tag == 'e-state':
				state.append(gdchild.attrib['id'])
	#print state
	# Given a start state
	choice = []
	prob = []
	end = []
	for child in root:
		for gdchild in child:
			if gdchild.tag == 'event' and gdchild.attrib['state1ID'] == start:
				choice.append(gdchild.attrib['name'])
				prob.append(gdchild.attrib['value'])
				end.append(gdchild.attrib['state2ID'])
	# Make decision
	rand = random.random()
	flag = 0
	sum_prob = [0] * len(prob)
	sum_prob[0] = float(prob[0])
	for i in range(1, len(prob)):
		sum_prob[i] = sum_prob[i-1] + float(prob[i])
	sum_prob[len(prob)-1] = 1
	for i in range(0, len(prob)-1):
		if rand > sum_prob[i] and rand < sum_prob[i+1]:
			output = i+1
			flag = 1
		if flag == 0:
			output = 0
	# Output the chosen label and output state
	return choice[output], end[output], rand

def map_to_one_group(choice, folder):
	f = open(folder + '/' + choice)
	line = f.readlines()
	f.close()
	picked = random.choice(line)
	value = picked.split(' ')
	timing = value[0]
	size = value[1].strip()
	return float(timing), int(size)

def map_size_to_length(length,size, size_bin):
	group = 5
	for i in range(len(size_bin)-1):
		if size > size_bin[i] and size <= size_bin[i+1]:
			group = i
			break
	return length[group], group

# Cut list into 16 chunks
def chunks(seq, size):
	newseq = []
	splitsize = 1.0/size*len(seq)
	for i in range(size):
		    newseq.append(seq[int(round(i*splitsize)):int(round((i+1)*splitsize))])
	return newseq

def divide_into_group(size_bin, length, folder):
	group = [[] for i in range(len(size_bin)+1)]
	working_dir = os.path.dirname(os.path.realpath(__file__))
	for i in range(len(size_bin)+1):
		f = open(working_dir + '/'+ folder + '/' + str(i))
		line = f.readlines()
		f.close()
		chunk = chunks(line, 16**length[i])
		group[i]+=chunk
	return group


def cut_fte_into_pieces(fte_output,filename, start, length, size_bin, all_group, folder, start_seed):
	fte_bin = []
	one_seed = start_seed
	while fte_output:
		# Make decision on each step to generate a symbol
		choice, end, rand = read_hmm(filename,start, one_seed)
		timing,size = map_to_one_group(choice, folder)
		start = end
		one_seed = rand
		one_length, group = map_size_to_length(length,size, size_bin)
		# If the fte output has enough length
		if one_length <= len(fte_output):		
			hex_string = fte_output[:one_length]
			int_num = int(hex_string, 16)
			picked_group = all_group[group][int_num]
			one_entry = random.choice(picked_group).strip()
			fte_bin.append(one_entry)
			fte_output = fte_output[one_length:]
		# Else pad it (with '013c') to target size
		else:
			fte_output += '013c'
			#print 'error'
			#print one_length
			#print len(fte_output)
	return fte_bin
	
def transform_string(input_string):
	# parameters
	input_length = 450
	start_seed = 42
	start = '2'
	filename = 'client-payload-output.fsa'
	folder_size = 'client-payload-size-uniq-obs'
	folder_symbol = 'client-payload-obs'
	timing_bin = [0.025]
	size_bin = [10,20,35,53,65]
	length = [1,2,3,2,3,3]
	# Encode as hex
	hex_string = input_string.encode('HEX')
	# Do original FTE
	regex = '^[0-9a-f]+$'
	#fixed_slice = 512
	fixed_slice = 150
	dfa = regex2dfa.regex2dfa(regex)
	fteObj = fte.encoder.DfaEncoder(dfa, fixed_slice)
	client_ciphertext = fteObj.encode(hex_string)
	print len(client_ciphertext)
	print client_ciphertext
	all_group = divide_into_group(size_bin, length, folder_size)
	#print client_ciphertext[0]
	fte_bin = cut_fte_into_pieces(client_ciphertext,filename, start, length, size_bin, all_group, folder_symbol, start_seed)
	#print len(fte_bin)
	return fte_bin


if __name__ == '__main__':
	input_string = 'hello world'
	output = transform_string(input_string)
	print len(output)	






















		
	
	
	
