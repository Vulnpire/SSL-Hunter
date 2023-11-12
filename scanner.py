import threading
import os

class SSLChecker:

        def __init__(
            self,mass_scan_results_file = "masscanResults.txt",
            ips_file="ips.txt"
        ):
            self.mass_scan_results_file=mass_scan_results_file
            self.ips_file = ips_file

        def check_and_create_files(self,*file_paths):
            for file_path in file_paths:
                if not os.path.exists(file_path):
                    #If the file doesn't exist, create it
                    with open(file_path, "w") as file:
                        pass
                    print(f'File "{file_path}" has been created')


        def main(self):
            self.check_and_create_files(self.mass_scan_results_file,self.ips_file)

if __name__ == "__main__":
    ssl_checker = SSLChecker()
    ssl_checker.main()