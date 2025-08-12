import os


class FileHandler:
    
    def __init__(self, file_path):
        
        self.filePath = file_path
        if os.path.exists(file_path):
            
            self.fileId = None
            self.fileSize = os.path.getsize(file_path)
            self.fileSender = None
            self.fileRecivingTime = None
            self.fileFormat = os.path.splitext(file_path)
            self.fileSendingTime = None
        

    def readFile(self):
        if os.path.exists(self.filePath):
            with open(self.filePath, 'rb') as file:
                self.fileContent = file.read()
                file.close()
            return True
        return False

    def writeFile(self, content):
        if not os.path.exists(self.filePath):
            with open(self.filePath, 'rb') as file:
                try:
                    file.write(content)
                except:
                    return False
            return True
        return False

    def saveRecord(self):
        pass


    def encryptFile(self, mode, specialFormat=None):
        pass

    def decryptFile(self, mode, specialFormat=None):
        pass

        
        
        
