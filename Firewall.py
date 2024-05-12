import tkinter as tk
from tkinter import messagebox


class Firewall:

    def __init__(self):
        self.rules = []

    def add_rule(self, Source_IP, Destination_IP, Source_Port, Destination_Port, Protocol):

        if not type(Source_IP) is str:
            raise ValueError(
                "Sorry! The Source IP address is INVALID.Try to enter correct IP address")

        if not type(Destination_IP) is str:
            raise ValueError(
                "Sorry! The Destination IP address is INVALID.Try to enter correct IP address")

        if not type(Source_Port) is int or Source_Port < 0 or Source_Port > 65535:
            raise ValueError(
                "Sorry! The Destination IP is INVALID.Should be an integer between 0 and 65535.")

        if not type(Destination_Port) is int or Source_Port < 0 or Source_Port > 65535:
            raise ValueError(
                "Sorry! The Destination Port is INVALID.Should be an integer between 0 and 65535.")

        if not type(Protocol) is str:
            raise ValueError(
                "Sorry! The Protocol is INVALID.Try to enter correct Protocol")

        rule = {
            'Source_IP': Source_IP,
            'Destination_IP': Destination_IP,
            'Source_Port': Source_Port,
            'Destination_Port': Destination_Port,
            'Protocol': Protocol
        }
        self.rules.append(rule)

    def is_packet_allowed(self, packet):
        for rule in self.rules:
            check = 0
            if (rule['Source_IP'] == '*' or rule['Source_IP'] == packet['Source_IP']):
                check = check + 1
            if (rule['Destination_IP'] == '*' or rule['Destination_IP'] == packet['Destination_IP']):
                check = check + 1
            if (rule['Source_Port'] == '*' or rule['Source_Port'] == packet['Source_Port']):
                check = check + 1
            if (rule['Destination_Port'] == '*' or rule['Destination_Port'] == packet['Destination_Port']):
                check = check + 1
            if (rule['Protocol'] == '*' or rule['Protocol'] == packet['Protocol']):
                check = check + 1
            if (check == 5):
                return True
        return False


class FirewallApp:

    def __init__(self, master):
        # Initialize the instance variables
        self.master = master
        self.master.title("Firewall GUI")

        # Create an instance of the Firewall class
        self.firewall = Firewall()

        # Create and set up the GUI widget
        self.Widgets()

    def Widgets(self):

        # Label For Source IP
        tk.Label(
            self.master,
            text=("Source IP :"),
            font=("Helvetica", 10, "bold"),  # Specify the font
            padx=75,        # Add horizontal padding
            pady=6,         # Add vertical padding
            bg="azure",     # Set background color
            fg="#63017a"

        ).grid(row=0, column=0, sticky="e")  # Align the label to the east (right)

        # Entry For Source IP
        self.source_ip_entry = tk.Entry(
            self.master,
            width=18,  # Set the width of the entry widget
            font=("Helvetica", 12, "italic"),  # Specify the font
        )
        # Add horizontal padding
        self.source_ip_entry.grid(row=0, column=1, padx=10, ipady=6, ipadx=10)

        # Label For Destination IP
        tk.Label(
            self.master,
            text=("Destination IP :"),
            font=("Helvetica", 10, "bold"),  # Specify the font
            padx=62,          # Add horizontal padding
            pady=6,           # Add vertical padding
            bg="azure",       # Set background color
            fg="#63017a",     # Set font color
        ).grid(row=1, column=0, sticky="e")  # Align the label to the east (right)

        # Entry For Destination IP
        self.destination_ip_entry = tk.Entry(
            self.master,
            width=18,  # Set the width of the entry widget
            font=("Helvetica", 12, "italic"),  # Specify the font
        )
        self.destination_ip_entry.grid(
            row=1, column=1, pady=10, padx=10, ipady=6, ipadx=10)  # Add horizontal padding

        # Label For Source Port
        tk.Label(
            self.master,
            text=("Source Port :"),
            font=("Helvetica", 10, "bold"),  # Specify the font
            padx=67,          # Add horizontal padding
            pady=6,           # Add vertical padding
            bg="azure",       # Set background color
            fg="#63017a",     # Set font color
        ).grid(row=2, column=0, sticky="e")  # Align the label to the east (right)

        # Entry For Source Port
        self.source_port_entry = tk.Entry(
            self.master,
            width=18,  # Set the width of the entry widget
            font=("Helvetica", 12, "italic"),  # Specify the font
        )
        self.source_port_entry.grid(
            row=2, column=1, pady=10, padx=10, ipady=6, ipadx=10)  # Add horizontal padding

        # Label For Destination Port
        tk.Label(
            self.master,
            text=("Destination Port :"),
            font=("Helvetica", 10, "bold"),  # Specify the font
            padx=55,          # Add horizontal padding
            pady=6,           # Add vertical padding
            bg="azure",       # Set background color
            fg="#63017a",     # Set font color
        ).grid(row=3, column=0, sticky="e")  # Align the label to the east (right)

        # Entry For Destination Port
        self.destination_port_entry = tk.Entry(
            self.master,
            width=18,  # Set the width of the entry widget
            font=("Helvetica", 12, "italic"),  # Specify the font
        )
        self.destination_port_entry.grid(
            row=3, column=1, pady=10, padx=10, ipady=6, ipadx=10)  # Add horizontal padding

        # Label For Protocol
        tk.Label(
            self.master,
            text=("Protocol :"),
            font=("Helvetica", 10, "bold"),  # Specify the font
            padx=77,          # Add horizontal padding
            pady=6,           # Add vertical padding
            bg="azure",       # Set background color
            fg="#63017a",     # Set font color
        ).grid(row=4, column=0, sticky="e")  # Align the label to the east (right)

        # Entry For Protocol
        self.protocol_entry = tk.Entry(
            self.master,
            width=18,  # Set the width of the entry widget
            font=("Helvetica", 12, "italic"),  # Specify the font
        )
        # Add horizontal padding
        self.protocol_entry.grid(
            row=4, column=1, pady=10, padx=10, ipady=6, ipadx=10)

        # Button to add a rule
        add_rule_button = tk.Button(
            self.master,
            text="Add Rule",
            command=self.add_rule,
            bg="pink",        # Set the background color to green
            fg="#63017a",        # Set the text color to white
            font=("Helvetica", 14),  # Set the font size to 14 points
        )
        add_rule_button.grid(row=5, column=0, columnspan=2, pady=10)

        # Button to check if a packet is allowed
        check_packet_button = tk.Button(
            self.master,
            text="Check Packet",
            command=self.check_packet,
            bg="light green",        # Set the background color to green
            fg="#63017a",        # Set the text color to white
            font=("Helvetica", 14),  # Set the font size to 14 points
        )
        check_packet_button.grid(row=6, column=0, columnspan=2, pady=10)

    # Adding Rule To Rules List

    def add_rule(self):
        Source_IP = self.source_ip_entry.get()
        Destination_IP = self.destination_ip_entry.get()
        Source_Port = int(self.source_port_entry.get())
        Destination_Port = int(self.destination_port_entry.get())
        Protocol = self.protocol_entry.get()

        try:
            self.firewall.add_rule(
                Source_IP, Destination_IP, Source_Port, Destination_Port, Protocol)
            messagebox.showinfo("Rule Added", "Rule added successfully!")
        except ValueError as e:
            messagebox.showerror("Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")

    # Checking Packet
    def check_packet(self):
        packet = {
            'Source_IP': self.source_ip_entry.get(),
            'Destination_IP': self.destination_ip_entry.get(),
            'Source_Port': int(self.source_port_entry.get()),
            'Destination_Port': int(self.destination_port_entry.get()),
            'Protocol': self.protocol_entry.get()
        }

        try:
            if self.firewall.is_packet_allowed(packet):
                messagebox.showinfo("Packet Allowed", "Packet is allowed!")
            else:
                messagebox.showwarning("Packet Blocked", "Packet is blocked!")

        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")


def main():
    try:
        root = tk.Tk()
        app = FirewallApp(root)
        root.mainloop()
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()
