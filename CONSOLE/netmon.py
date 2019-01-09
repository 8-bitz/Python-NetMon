import socket
import tkinter as tk
import os
from scapy.all import *

def main():
	root = tk.Tk()
	ipAddr = (socket.gethostbyname(socket.gethostname()))
	ipDictionary = {}
	ipSortedDictionary = {}
	ipToNameDict = {}
	ipSet = set()
	infList = get_windows_if_list()
	top10Counter = 0
	interface = infList[0].get("name")
	fltr = ("DST HOST " + ipAddr + " AND TCP")

	while True:	
		packets = sniff(iface=interface, count=50)
		ipSet.clear()
		for x in range(0,len(packets)):	
			if(packets[x].haslayer(IP)):
				if ipAddr == packets[x][IP].src:
					ipSet.add(packets[x][IP].dst)			
		for i in ipSet:
			#print(i)
			for x in range(0,len(packets)):	
				if(packets[x].haslayer(IP)):
					if i == packets[x][IP].dst:
						if i in ipDictionary:
							ipDictionary[i] = ipDictionary[i] + 1
						else:
							ipDictionary[i] = 1
		ipSortedDictionary = sorted(ipDictionary, key=ipDictionary.get, reverse=True)
		#print("1 - ****************")
		top10Counter = 0
		os.system('cls') # on windows
		for i in ipSortedDictionary:
			if i not in ipToNameDict:
				try:
					ipToNameDict[i] = 	socket.gethostbyaddr(i)[0]
				except:
					ipToNameDict[i] = ""			
			if top10Counter < 10:			
				print (i, ipDictionary[i], ipToNameDict[i])			
			top10Counter = top10Counter + 1
		#print("2 - ****************")
		#input("PRESS ENTER TO CONTINUE.")

if __name__ == "__main__":
	main()
			