import socket
import tkinter as tk
import os
from scapy.all import *
import threading

ipAddr = (socket.gethostbyname(socket.gethostname()))
ipDictionary = {}
ipSortedDictionary = {}
ipToNameDict = {}
ipSet = set()
infList = get_windows_if_list()
interface = infList[0].get("name")
totalPackets = 0
talkers = []
for x in range (0, 10):
	talkers.append(["",0,""])

class Application(tk.Frame):

	def __init__(self, master):
		""" Initialize the Frame"""
		
		tk.Frame.__init__(self, master)

		nwUpdThread = threading.Thread(target=self.updateNetworkInfo) # make sure thread is killed when application closed:
		nwUpdThread.start()
		self.labelText1 = ""
		self.labelText2 = ""
		self.labelText3 = ""
		self.labelText4 = ""
		self.labelText5 = ""
		self.labelText6 = ""
		self.labelText7 = ""
		self.labelText8 = ""
		self.labelText9 = ""
		self.labelText10 = ""
		
		self.label1 = tk.Label(master)
		self.label2 = tk.Label(master)
		self.label3 = tk.Label(master)
		self.label4 = tk.Label(master)
		self.label5 = tk.Label(master)
		self.label6 = tk.Label(master)
		self.label7 = tk.Label(master)
		self.label8 = tk.Label(master)
		self.label9 = tk.Label(master)
		self.label10 = tk.Label(master)		
		
		self.label1.grid(row=0, column=0, sticky="w")
		self.label2.grid(row=1, column=0, sticky="w")
		self.label3.grid(row=2, column=0, sticky="w")
		self.label4.grid(row=3, column=0, sticky="w")
		self.label5.grid(row=4, column=0, sticky="w")
		self.label6.grid(row=5, column=0, sticky="w")
		self.label7.grid(row=6, column=0, sticky="w")
		self.label8.grid(row=7, column=0, sticky="w")
		self.label9.grid(row=8, column=0, sticky="w")
		self.label10.grid(row=9, column=0, sticky="w")
		
		self.label1.configure(text = self.labelText1)
		self.label2.configure(text = self.labelText2)
		self.label3.configure(text = self.labelText3)
		self.label4.configure(text = self.labelText4)
		self.label5.configure(text = self.labelText5)
		self.label6.configure(text = self.labelText6)
		self.label7.configure(text = self.labelText7)
		self.label8.configure(text = self.labelText8)
		self.label9.configure(text = self.labelText9)
		self.label10.configure(text = self.labelText10)
		self.updater()
	

	def updateNetworkInfo(self):
		while True:
			top10Counter = 0
			print("updating network info")
			global totalPackets
			global talkers
			listItem = []
			top10talkers = []
			packets = sniff(iface=interface, count=250)		#Sniff the first 25 packets
			ipSet.clear()									#Clear the SET containing IP's from the capture
			for x in range(0,len(packets)):					#For all discovered packets
				if(packets[x].haslayer(IP)):				#Does it have an IP layer
					if ipAddr == packets[x][IP].src:		#if it was sent from the local computer
						ipSet.add(packets[x][IP].dst)		#add the destination IP to the IP set	
			for i in ipSet:									#For every IP discovered		
				for x in range(0,len(packets)):				#Go through every packet
					if(packets[x].haslayer(IP)):			#if it has an IP layer
						if i == packets[x][IP].dst:			#if the destination IP is the same as the once currently selected in the SET
							totalPackets = totalPackets + 1	#track total number of packets examined
							if i in ipDictionary:			#check if it is in the IP Dictionary
								ipDictionary[i] = ipDictionary[i] + 1	#If it is, update the count of packets
							else:							#else
								ipDictionary[i] = 1			#initialize with 1 packet
			ipSortedDictionary = sorted(ipDictionary, key=ipDictionary.get, reverse=True)		#Sort the dictionary		
			for i in ipSortedDictionary:					#for every entry in the sorted dictionary
				if i not in ipToNameDict:					#create a name to IP dictionary 
					try:									#if IP not in the dictionary
						ipToNameDict[i] = 	socket.gethostbyaddr(i)[0]	#try to resolve the name 
					except:
						ipToNameDict[i] = ""				#if failed, set the blank
				if top10Counter < 10:				#for the top 10 entries		
					top10Counter = top10Counter + 1
					listItem = [i, ipDictionary[i], ipToNameDict[i]]
					top10talkers.append(listItem)
					#print (top10Counter, listItem)	
			if (len(top10talkers) < 10):
				for x in range(len(top10talkers),10):
					top10talkers.append(["",0,""])
					#print("Padding top talkers")
			talkers = top10talkers
			#print(talkers)		
			#print(str(totalPackets))	
			print("update network info COMPLETED")
		return(talkers)

	def updater(self):				# maybe run the updater as a thread??? and periodically pull the current data?
		#print("In Updater")
		#talkers = self.updateNetworkInfo()
		if (totalPackets == 0):
			self.labelText1 = talkers[0][0] + "  (0%) [" + talkers[0][2] + "]"
			self.labelText2 = talkers[1][0] + "  (0%) [" + talkers[1][2] + "]"
			self.labelText3 = talkers[2][0] + "  (0%) [" + talkers[2][2] + "]"
			self.labelText4 = talkers[3][0] + "  (0%) [" + talkers[3][2] + "]"
			self.labelText5 = talkers[4][0] + "  (0%) [" + talkers[4][2] + "]"
			self.labelText6 = talkers[5][0] + "  (0%) [" + talkers[5][2] + "]"
			self.labelText7 = talkers[6][0] + "  (0%) [" + talkers[6][2] + "]"
			self.labelText8 = talkers[7][0] + "  (0%) [" + talkers[7][2] + "]"
			self.labelText9 = talkers[8][0] + "  (0%) [" + talkers[8][2] + "]"
			self.labelText10 = talkers[9][0] + "  (0%) [" + talkers[9][2] + "]"
		else:
			self.labelText1 = talkers[0][0] + "  (" + str(round((talkers[0][1] / totalPackets) * 100,2)) + "%) [" + talkers[0][2] + "]"
			self.labelText2 = talkers[1][0] + "  (" + str(round((talkers[1][1] / totalPackets) * 100,2)) + "%) [" + talkers[1][2] + "]"
			self.labelText3 = talkers[2][0] + "  (" + str(round((talkers[2][1] / totalPackets) * 100,2)) + "%) [" + talkers[2][2] + "]"
			self.labelText4 = talkers[3][0] + "  (" + str(round((talkers[3][1] / totalPackets) * 100,2)) + "%) [" + talkers[3][2] + "]"
			self.labelText5 = talkers[4][0] + "  (" + str(round((talkers[4][1] / totalPackets) * 100,2)) + "%) [" + talkers[4][2] + "]"
			self.labelText6 = talkers[5][0] + "  (" + str(round((talkers[5][1] / totalPackets) * 100,2)) + "%) [" + talkers[5][2] + "]"
			self.labelText7 = talkers[6][0] + "  (" + str(round((talkers[6][1] / totalPackets) * 100,2)) + "%) [" + talkers[6][2] + "]"
			self.labelText8 = talkers[7][0] + "  (" + str(round((talkers[7][1] / totalPackets) * 100,2)) + "%) [" + talkers[7][2] + "]"
			self.labelText9 = talkers[8][0] + "  (" + str(round((talkers[8][1] / totalPackets) * 100,2)) + "%) [" + talkers[8][2] + "]"
			self.labelText10 = talkers[9][0] + "  (" + str(round((talkers[9][1] / totalPackets) * 100,2)) + "%) [" + talkers[9][2] + "]"
		
		self.label1.configure(text = self.labelText1, anchor="w")
		self.label2.configure(text = self.labelText2, anchor="w")
		self.label3.configure(text = self.labelText3, anchor="w")
		self.label4.configure(text = self.labelText4, anchor="w")
		self.label5.configure(text = self.labelText5, anchor="w")
		self.label6.configure(text = self.labelText6, anchor="w")
		self.label7.configure(text = self.labelText7, anchor="w")
		self.label8.configure(text = self.labelText8, anchor="w")
		self.label9.configure(text = self.labelText9, anchor="w")
		self.label10.configure(text = self.labelText10, anchor="w")
		
		self.label1.after(5000, self.updater)
		print("label updated")
		
		
def main():
	root = tk.Tk()	
	Application(root)
	root.mainloop()

if __name__ == "__main__":
	main()
			