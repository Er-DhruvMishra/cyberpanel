import json
import os
import time


class InstallLog:
    fileName = "/var/log/installLogs.txt"
    currentPercent = '10'
    # Upstream posted every install step (with the server IP) to the vendor.
    # IndiansCloud keeps the log local; set INDIANSCLOUD_INSTALL_STATUS_URL to an
    # https receiver of your own to forward steps. Empty by default: no request.
    LogURL = os.environ.get('INDIANSCLOUD_INSTALL_STATUS_URL', '')
    ServerIP = ''

    @staticmethod
    def writeToFile(message):

        if message.find(',') == -1:
            message = '%s,%s' % (message, InstallLog.currentPercent)
        elif message.find('mount -o') > -1 or message.find('usermod -G lscpd,') > -1:
            message = '%s,%s' % (message.replace(',', '-'), InstallLog.currentPercent)
        else:
            try:
                InstallLog.currentPercent = message.split(',')[1]
            except:
                pass

        file = open(InstallLog.fileName,'a')
        file.writelines("[" + time.strftime(
                    "%m.%d.%Y_%H-%M-%S") + "] " + message + "\n")
        file.close()

        if not InstallLog.LogURL.startswith('https://'):
            return
        try:
            import requests
            finalData = json.dumps({'ipAddress': InstallLog.ServerIP, "InstallCyberPanelStatus": message})
            requests.post(InstallLog.LogURL, data=finalData, timeout=10)
        except:
            pass
