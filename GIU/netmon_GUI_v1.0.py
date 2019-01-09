import socket
import tkinter as tk
import os
from scapy.all import *

ipAddr = (socket.gethostbyname(socket.gethostname()))
ipDictionary = {}
ipSortedDictionary = {}
ipToNameDict = {}
ipSet = set()
infList = get_windows_if_list()
interface = infList[0].get("name")
totalPackets = 0

class Application(tk.Frame):

	def __init__(self, master):
		""" Initialize the Frame"""
		tk.Frame.__init__(self, master)
		self.grid()
		self.createWidgets()
		self.updater()
	
	def createWidgets(self):
		self.var1 = tk.StringVar()
		self.var2 = tk.StringVar()
		self.var3 = tk.StringVar()
		self.var4 = tk.StringVar()
		self.var5 = tk.StringVar()
		self.var6 = tk.StringVar()
		self.var7 = tk.StringVar()
		self.var8 = tk.StringVar()
		self.var9 = tk.StringVar()
		self.var10 = tk.StringVar()		
		self.label1 = tk.Label(self, textvariable = self.var1, anchor="w", width=50, relief=tk.RAISED)
		self.label2 = tk.Label(self, textvariable = self.var2, anchor="w", width=50, relief=tk.RAISED)
		self.label3 = tk.Label(self, textvariable = self.var3, anchor="w", width=50, relief=tk.RAISED)
		self.label4 = tk.Label(self, textvariable = self.var4, anchor="w", width=50, relief=tk.RAISED)
		self.label5 = tk.Label(self, textvariable = self.var5, anchor="w", width=50, relief=tk.RAISED)
		self.label6 = tk.Label(self, textvariable = self.var6, anchor="w", width=50, relief=tk.RAISED)
		self.label7 = tk.Label(self, textvariable = self.var7, anchor="w", width=50, relief=tk.RAISED)
		self.label8 = tk.Label(self, textvariable = self.var8, anchor="w", width=50, relief=tk.RAISED)
		self.label9 = tk.Label(self, textvariable = self.var9, anchor="w", width=50, relief=tk.RAISED)
		self.label10 = tk.Label(self, textvariable = self.var10, anchor="w", width=50, relief=tk.RAISED)

	def updateNetworkInfo():
		top10Counter = 0
		global totalPackets
		listItem = []
		top10talkers = []
		packets = sniff(iface=interface, count=100)		#Sniff the first 25 packets
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
		return top10talkers
		#print(str(totalPackets))	

	def updater():	
		talkers = updateNetworkInfo()
	
		var1.set(talkers[0][0] + "  (" + str(round((talkers[0][1] / totalPackets) * 100,2)) + "%) [" + talkers[0][2] + "]")
		var2.set(talkers[1][0] + "  (" + str(round((talkers[1][1] / totalPackets) * 100,2)) + "%) [" + talkers[1][2] + "]")
		var3.set(talkers[2][0] + "  (" + str(round((talkers[2][1] / totalPackets) * 100,2)) + "%) [" + talkers[2][2] + "]")
		var4.set(talkers[3][0] + "  (" + str(round((talkers[3][1] / totalPackets) * 100,2)) + "%) [" + talkers[3][2] + "]")
		var5.set(talkers[4][0] + "  (" + str(round((talkers[4][1] / totalPackets) * 100,2)) + "%) [" + talkers[4][2] + "]")
		var6.set(talkers[5][0] + "  (" + str(round((talkers[5][1] / totalPackets) * 100,2)) + "%) [" + talkers[5][2] + "]")
		var7.set(talkers[6][0] + "  (" + str(round((talkers[6][1] / totalPackets) * 100,2)) + "%) [" + talkers[6][2] + "]")
		var8.set(talkers[7][0] + "  (" + str(round((talkers[7][1] / totalPackets) * 100,2)) + "%) [" + talkers[7][2] + "]")
		var9.set(talkers[8][0] + "  (" + str(round((talkers[8][1] / totalPackets) * 100,2)) + "%) [" + talkers[8][2] + "]")
		var10.set(talkers[9][0] + "  (" + str(round((talkers[9][1] / totalPackets) * 100,2)) + "%) [" + talkers[9][2] + "]")

		label1.pack()
		label2.pack()
		label3.pack()
		label4.pack()
		label5.pack()
		label6.pack()
		label7.pack()
		label8.pack()
		label9.pack()
		label10.pack()
		
		self.after(1000,self.updater)

def main():
	root = tk.Tk()	
	#talkers = []
	#fltr = ("DST HOST " + ipAddr + " AND TCP")

	#for x in range(0,25):	
	#	#os.system('cls') # on windows					#clear the console screen
	#	talkers = updateNetworkInfo()
	#	print(len(talkers))
	#	print(str(totalPackets))
	#	print("*****************************")

	#var1 = tk.StringVar()
	#var2 = tk.StringVar()
	#var3 = tk.StringVar()
	#var4 = tk.StringVar()
	#var5 = tk.StringVar()
	#var6 = tk.StringVar()
	#var7 = tk.StringVar()
	#var8 = tk.StringVar()
	#var9 = tk.StringVar()
	#var10 = tk.StringVar()	

	#label1 = tk.Label(root, textvariable = var1, anchor="w", width=50, relief=tk.RAISED)
	#label2 = tk.Label(root, textvariable = var2, anchor="w", width=50, relief=tk.RAISED)
	#label3 = tk.Label(root, textvariable = var3, anchor="w", width=50, relief=tk.RAISED)
	#label4 = tk.Label(root, textvariable = var4, anchor="w", width=50, relief=tk.RAISED)
	#label5 = tk.Label(root, textvariable = var5, anchor="w", width=50, relief=tk.RAISED)
	#label6 = tk.Label(root, textvariable = var6, anchor="w", width=50, relief=tk.RAISED)
	#label7 = tk.Label(root, textvariable = var7, anchor="w", width=50, relief=tk.RAISED)
	#label8 = tk.Label(root, textvariable = var8, anchor="w", width=50, relief=tk.RAISED)
	#label9 = tk.Label(root, textvariable = var9, anchor="w", width=50, relief=tk.RAISED)
	#label10 = tk.Label(root, textvariable = var10, anchor="w", width=50, relief=tk.RAISED)

	#print(talkers[0])
	#print(talkers[1])
	#print(talkers[2])
	#print(talkers[3])
	#print(talkers[4])
	#print(talkers[5])
	#print(talkers[6])
	#print(talkers[7])
	#print(talkers[8])
	#print(talkers[9])
	
	#var1.set(talkers[0][0] + "  (" + str(round((talkers[0][1] / totalPackets) * 100,2)) + "%) [" + talkers[0][2] + "]")
	#var2.set(talkers[1][0] + "  (" + str(round((talkers[1][1] / totalPackets) * 100,2)) + "%) [" + talkers[1][2] + "]")
	#var3.set(talkers[2][0] + "  (" + str(round((talkers[2][1] / totalPackets) * 100,2)) + "%) [" + talkers[2][2] + "]")
	#var4.set(talkers[3][0] + "  (" + str(round((talkers[3][1] / totalPackets) * 100,2)) + "%) [" + talkers[3][2] + "]")
	#var5.set(talkers[4][0] + "  (" + str(round((talkers[4][1] / totalPackets) * 100,2)) + "%) [" + talkers[4][2] + "]")
	#var6.set(talkers[5][0] + "  (" + str(round((talkers[5][1] / totalPackets) * 100,2)) + "%) [" + talkers[5][2] + "]")
	#var7.set(talkers[6][0] + "  (" + str(round((talkers[6][1] / totalPackets) * 100,2)) + "%) [" + talkers[6][2] + "]")
	#var8.set(talkers[7][0] + "  (" + str(round((talkers[7][1] / totalPackets) * 100,2)) + "%) [" + talkers[7][2] + "]")
	#var9.set(talkers[8][0] + "  (" + str(round((talkers[8][1] / totalPackets) * 100,2)) + "%) [" + talkers[8][2] + "]")
	#var10.set(talkers[9][0] + "  (" + str(round((talkers[9][1] / totalPackets) * 100,2)) + "%) [" + talkers[9][2] + "]")

	#label1.pack()
	#label2.pack()
	#label3.pack()
	#label4.pack()
	#label5.pack()
	#label6.pack()
	#label7.pack()
	#label8.pack()
	#label9.pack()
	#label10.pack()
	app = Application(root)
	root.mainloop()

if __name__ == "__main__":
	main()
			