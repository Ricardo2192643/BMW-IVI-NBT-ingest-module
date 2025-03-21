# Copyright 2022 Ricardo Manuel da Costa Marques
#
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published
# by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
# 
#
# Ingest module by Ricardo Marques Master's student in Cybersecurity and Forensic Informatics
# Polytechnic Institute of Leiria - Portugal
#
# This ingest module allows you to investigate SQLite database of
# BMW brand In-Vehicle Infotainment systems, NBT model year 2017
# Find data such as contacts, messages, Bluetooth mac address
# MEI, IMSI, call history, which devices were connected
# music tastes, web history, cookies and musics groups
#
# This ingest module was tested with Autopsy version 4.21.0
#
# Instructions for using this ingest module:
# Tools - Python Plugins and put ingest module in that folder



import jarray
import inspect
import os
from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException
from java.util.logging import Level
from java.util import ArrayList
from java.io import File
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.casemodule.services import Blackboard


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
# TODO: Rename this to something more specific. Search and replace for it because it is used a few times
class IviBmwDbIngestModuleFactory(IngestModuleFactoryAdapter):

    # TODO: give it a unique name.  Will be shown in module list, logs, etc.
    moduleName = "Infotainment BMW NBT"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "extract phone numbers,email,address,country,call and message,connected devices,bluetooth,macaddress,EMEI,IMSI,model smartphone,favorite songs"
     
    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        # TODO: Change the class name to the name you'll make below
        return IviBmwDbIngestModule()


# Data Source-level ingest module.  One gets created per data source.
# TODO: Rename this to something more specific. Could just remove "Factory" from above name.
class IviBmwDbIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(IviBmwDbIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/4.4/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    # TODO: Add any setup code that you need here.
    def startUp(self, context):
        
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException("Oh No!")
        self.context = context

    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/4.4/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/4.4/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    # TODO: Add your analysis code in here.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        # Find files named contacts.db, regardless of parent path
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "contactbook_%.db")

        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db")
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the contacts table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT contact_card_phone.Contact_ID, "
                                    "contact_card_phone.GivenName, contact_card_phone.FamilyName, "
                                    "contact_card_phone.Url, contact_card_phone.organisation FROM contact_card_phone "
                                    "ORDER BY contact_card_phone.GivenName")
								  
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    Contact_ID = resultSet.getString("Contact_ID")
                    GivenName = resultSet.getString("GivenName")
                    FamilyName = resultSet.getString("FamilyName")
                    Url = resultSet.getString("Url")
                    organisation = resultSet.getString("organisation")
                    
                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")
                
                
                # Make an artifact on the blackboard, TSK_CONTACT and give it attributes for each of the fields
                art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_CONTACT)
                family_name_att_type = blackboard.getOrAddAttributeType('BMW_FAMILY_NAME_TYPE',BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "FamilyName")
                attributes = ArrayList()
                
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_ID.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, Contact_ID))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, GivenName))
                attributes.add(BlackboardAttribute(family_name_att_type,IviBmwDbIngestModuleFactory.moduleName, FamilyName))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, Url))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ORGANIZATION.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, organisation))
                           
                art.addAttributes(attributes)
                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())     

        #contact phone
        arttttId = blackboard.getOrAddArtifactType("TSK_CONTACT_PHONE", "Contact Phone")
        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db")
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the contacts table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT contact_card_phone.Contact_ID, contact_card_phone.GivenName, "
								  "contact_card_phone.FamilyName, contact_card_phone.AdditionalName, "
								  "contact_card_phone.Url, contact_card_phone.organisation, "
								  "phone_data_phone.PhoneNumber FROM contact_card_phone "
								  "JOIN phone_data_phone ON contact_card_phone.Contact_ID = phone_data_phone.Contact_ID "
                                  "ORDER BY contact_card_phone.GivenName")
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    Contact_ID = resultSet.getString("Contact_ID")
                    GivenName = resultSet.getString("GivenName")
                    FamilyName = resultSet.getString("FamilyName")
                    PhoneNumber = resultSet.getString("PhoneNumber")

                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")
                
                
                # Make an artifact on the blackboard, TSK_CONTACT and give it attributes for each of the fields
                art = file.newArtifact(arttttId.getTypeID())
                family_name_att_type = blackboard.getOrAddAttributeType('BMW_FAMILY_NAME_TYPE',BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "FamilyName")
                attributes = ArrayList()
                
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_ID.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, Contact_ID))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, GivenName))
                attributes.add(BlackboardAttribute(family_name_att_type,IviBmwDbIngestModuleFactory.moduleName, FamilyName)) 
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, PhoneNumber))

                           
                art.addAttributes(attributes)
                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

        #contact email
        arttttIId = blackboard.getOrAddArtifactType("TSK_CONTACT_EMAIL", "Contact Email")
        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db")
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the contacts table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT contact_card_phone.Contact_ID, contact_card_phone.GivenName, "
								  "contact_card_phone.FamilyName, msg_data_phone.EmailAddr FROM contact_card_phone "								  
					              "JOIN msg_data_phone ON contact_card_phone.Contact_ID = msg_data_phone.Contact_ID "								  
								  "ORDER BY contact_card_phone.GivenName")
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    Contact_ID = resultSet.getString("Contact_ID")
                    GivenName = resultSet.getString("GivenName")
                    FamilyName = resultSet.getString("FamilyName")
                    EmailAddr = resultSet.getString("EmailAddr")
                    
                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")
                
                
                # Make an artifact on the blackboard, TSK_CONTACT and give it attributes for each of the fields
                art = file.newArtifact(arttttIId.getTypeID())
                family_name_att_type = blackboard.getOrAddAttributeType('BMW_FAMILY_NAME_TYPE',BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "FamilyName")
                attributes = ArrayList()
                
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_ID.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, Contact_ID))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, GivenName))
                attributes.add(BlackboardAttribute(family_name_att_type,IviBmwDbIngestModuleFactory.moduleName, FamilyName))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, EmailAddr))
               

                
                           
                art.addAttributes(attributes)
                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
                
        #contact address
        arttttIIId = blackboard.getOrAddArtifactType("TSK_CONTACT_ADDRESS", "Contact Address")
        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db")
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the contacts table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT contact_card_phone.Contact_ID, contact_card_phone.GivenName, "
								  "contact_card_phone.FamilyName, contact_card_phone.AdditionalName, "
								  "contact_card_phone.Url, contact_card_phone.organisation, "			
								  "address_phone.StreetHousenumber, address_phone.City, "
								  "address_phone.Country, address_phone.Postalcode FROM contact_card_phone "
								  "JOIN address_phone ON contact_card_phone.Contact_ID = address_phone.Contact_ID "
                                  "WHERE address_phone.crosssum > 0 "
								  "ORDER BY contact_card_phone.GivenName")
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    Contact_ID = resultSet.getString("Contact_ID")
                    GivenName = resultSet.getString("GivenName")
                    FamilyName = resultSet.getString("FamilyName")
                    StreetHousenumber = resultSet.getString("StreetHousenumber")
                    City = resultSet.getString("City")
                    Country = resultSet.getString("Country")
                    Postalcode = resultSet.getString("Postalcode")
                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")
                
                
                # Make an artifact on the blackboard, TSK_CONTACT and give it attributes for each of the fields
                art = file.newArtifact(arttttIIId.getTypeID())
                postal_code_att_type = blackboard.getOrAddAttributeType('BMW_POSTAL_CODE_TYPE',BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "PostalCode")
                family_name_att_type = blackboard.getOrAddAttributeType('BMW_FAMILY_NAME_TYPE',BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "FamilyName")

                attributes = ArrayList()
                
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_USER_ID.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, Contact_ID))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, GivenName))
                attributes.add(BlackboardAttribute(family_name_att_type,IviBmwDbIngestModuleFactory.moduleName, FamilyName)) 
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_LOCATION.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, StreetHousenumber))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_CITY.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, City))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COUNTRY.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, Country))
                attributes.add(BlackboardAttribute(postal_code_att_type,IviBmwDbIngestModuleFactory.moduleName, Postalcode))                 
                           
                art.addAttributes(attributes)
                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
                
        #bluetooth
        arttId = blackboard.getOrAddArtifactType("TSK_BLUETOOTH_ADDRESS", "Bluetooth Address")

        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db")
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the bluetooth table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT Origin, BtAddress FROM bluetooth")
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    Origin = resultSet.getString("Origin")
                    BtAddress = resultSet.getString("BtAddress")
                   
                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")
                
                
                # Make an artifact on the blackboard, TSK_BLUETOOTH_PAIRING and give it attributes for each of the fields
                art = file.newArtifact(arttId.getTypeID())
                
                bluetooth_address_att_type = blackboard.getOrAddAttributeType('BMW_BLUETOOTH_ADDRESS_TYPE',BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "BtAddress")
                
                attributes = ArrayList()
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ID.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, Origin))
                attributes.add(BlackboardAttribute(bluetooth_address_att_type,IviBmwDbIngestModuleFactory.moduleName, BtAddress)) 
                                         
                art.addAttributes(attributes)
                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
        
        #callstacks
        files = fileManager.findFiles(dataSource, "pm800%.a")

        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db" )
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the callstacks table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT CALLSTACKS.ID, CALLSTACKS.FN, CALLSTACKS.TEL_NR, STRFTIME('%s', CALLSTACKS.TIMESTAMP) AS TIMESTAMP FROM CALLSTACKS")
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    ID = resultSet.getString("ID")
                    if resultSet.getString("FN") == None:
                        FN = ""
                    else:
                        FN = resultSet.getString("FN")
                    TEL_NR = resultSet.getString("TEL_NR")
                    TIMESTAMP = resultSet.getInt("TIMESTAMP")
                    
                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")                
                
                # Make an artifact on the blackboard, TSK_CALLLOG and give it attributes for each of the fields
                art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_CALLLOG)
                attributes = ArrayList()
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ID.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, ID))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, FN))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, TEL_NR))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, long(TIMESTAMP)))
                
                art.addAttributes(attributes)
                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
                
        #bluetooth pairing, BluetoothAddress, EMEI, IMSI, MODEL TELEPHONE
        files = fileManager.findFiles(dataSource, "p%.db")

        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db")
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the bluetooth pairing, BluetoothAddress, EMEI, IMSI, MODEL TELEPHONE table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT SID, INFO_KEY, INFO_VALUE FROM CE_DEVICE_INFO WHERE INFO_KEY = 'IMEI' OR INFO_KEY = 'IMSI' OR INFO_KEY = 'BluetoothAddress' or INFO_KEY = 'Model' ORDER BY SID")
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    SID = resultSet.getString("SID")
                    INFO_KEY = resultSet.getString("INFO_KEY")
                    INFO_VALUE = resultSet.getString("INFO_VALUE")
                   
                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")
                
                
                # Make an artifact on the blackboard, TSK_BLUETOOTH_PAIRING and give it attributes for each of the fields
                art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_BLUETOOTH_PAIRING)
                attributes = ArrayList()
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ID.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, SID))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DESCRIPTION.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, INFO_KEY))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DEVICE_ID.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, INFO_VALUE))
                
                art.addAttributes(attributes)
                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
                
        #BROWSER
        files = fileManager.findFiles(dataSource, "BrowserUrls.db")

        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db")
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the BROWSER table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT urls.id, urls.title, urls.url, visits.datevisit FROM urls LEFT JOIN visits")
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    id = resultSet.getString("id")
                    title = resultSet.getString("title")
                    url = resultSet.getString("url")
                    datevisit = resultSet.getInt("datevisit")
                    urlid = resultSet.getString("urlid")
                        
                    
                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")
                
                
                # Make an artifact on the blackboard, TSK_WEB_HISTORY and give it attributes for each of the fields
                art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_HISTORY)
                attributes = ArrayList()
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ID.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, id))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TITLE.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, title))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, url))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, datevisit))
  
                art.addAttributes(attributes)
                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

        #COOKIES
        files = fileManager.findFiles(dataSource, "cookie.db")

        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db")
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the COOKIES table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT cookies.name, cookies.host, cookies.path, cookies.lastAccessed FROM cookies")
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    name = resultSet.getString("name")
                    host = resultSet.getString("host")
                    path = resultSet.getString("path")
                    lastAccessed = resultSet.getInt("lastAccessed")
                    
                        
                    
                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")
                
                
                # Make an artifact on the blackboard, TSK_WEB_COOKIE and give it attributes for each of the fields
                art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_COOKIE)
                attributes = ArrayList()
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, name))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, host))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PATH.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, path))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, lastAccessed))

                art.addAttributes(attributes)
                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

        #messages
        files = fileManager.findFiles(dataSource, "f2%.sqlite")

        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db" )
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the messages table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery('SELECT messages.id, messages.fromPhoneNumber, strftime("%s", substr(date,1,4) || "-" || substr(date,5,2) || "-" || substr(date,7,2) || "T" || substr(date,9,2) || ":" || substr(date,11,2) || ":" || substr(date,13,2)) as newdate, messages.subject FROM messages')
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    id = resultSet.getString("id")
                    fromPhoneNumber = resultSet.getString("fromPhoneNumber")
                    date = resultSet.getLong("newdate")
                    subject = resultSet.getString("subject")
                    
                    art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE)
                    
                    from_number_att_type = blackboard.getOrAddAttributeType('BMW_FROM_NUMBER_TYPE',BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "fromPhoneNumber")

                    attributes = ArrayList()
                    
                    attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ID.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, id))
                    attributes.add(BlackboardAttribute(from_number_att_type,IviBmwDbIngestModuleFactory.moduleName, fromPhoneNumber))
                    attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, date))
                    attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TEXT.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, subject))
                    

                
                
                    art.addAttributes(attributes)
                    try:
                        Case.getCurrentCase().getSleuthkitCase().getBlackboard().postArtifact(art, IviBmwDbIngestModuleFactory.moduleName)
                    except Blackboard.BlackboardException as e:
                        self.log(Level.SEVERE, "Error posting artifact " + art.getDisplayName())
                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")
                
       
        

        #mme_mediastores
        files = fileManager.findFiles(dataSource, "mme%")

        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db" )
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the mme_mediastores table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT msid, lastseen, mssname, name, identifier, mountpath FROM mediastores")
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    msid = resultSet.getString("msid") 
                    lastseen = resultSet.getLong("lastseen")
                    mssname = resultSet.getString("mssname")
                    name = resultSet.getString("name")
                    identifier = resultSet.getString("identifier")
                    mountpath = resultSet.getString("mountpath")
                   
                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")                
                
                # Make an artifact on the blackboard, TSK_DEVICE_INFO and give it attributes for each of the fields
                art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_DEVICE_INFO)
                attributes = ArrayList()
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ID.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, msid))
                
                timevalue = lastseen/1000000000
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, timevalue))
                
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DESCRIPTION.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, mssname))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, name))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DEVICE_ID.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, identifier))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PATH.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, mountpath))
               

                art.addAttributes(attributes)
                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
                
        #music and groups        
        artId = blackboard.getOrAddArtifactType("TSK_MUSIC_GROUPS", "Music Groups")

        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db" )
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the music and groups  table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT categorydata_custom.name FROM categorydata_custom")
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    name = resultSet.getString("name")
                    
                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")                
                
                # Make an artifact on the blackboard, TSK_DOWNLOAD_SOURCE and give it attributes for each of the fields
                art = file.newArtifact(artId.getTypeID())
                attributes = ArrayList()
                
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, name))
               


                art.addAttributes(attributes)
                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())                
             
        #software  
        artIId = blackboard.getOrAddArtifactType("TSK_SOFTWARE_INFO", "Software info")
        
        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db" )
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the software table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT software_info.version FROM software_info")
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    version = resultSet.getString("version")
                    
                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")                
                
                # Make an artifact on the blackboard, TSK_DOWNLOAD_SOURCE and give it attributes for each of the fields
                art = file.newArtifact(artIId.getTypeID())
                attributes = ArrayList()
                
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_VERSION.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, version))
               


                art.addAttributes(attributes)
                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

        #usbdetails
        artIIId = blackboard.getOrAddArtifactType("TSK_USB_DEVICEDETAILS", "Usb device details")
        
        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db" )
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the usbdetails table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT deviceserialno, lastseen FROM usbdevicedetails")
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    deviceserialno = resultSet.getString("deviceserialno")
                    lastseen = resultSet.getLong("lastseen")
                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")                
                
                # Make an artifact on the blackboard, TSK_DOWNLOAD_SOURCE and give it attributes for each of the fields
                art = file.newArtifact(artIIId.getTypeID())
                
                device_name_att_type = blackboard.getOrAddAttributeType('BMW_DEVICE_NAME_TYPE',BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "deviceserialno")

                attributes = ArrayList()
                
                
               
                attributes.add(BlackboardAttribute(device_name_att_type,IviBmwDbIngestModuleFactory.moduleName, deviceserialno)) 
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, lastseen))


                art.addAttributes(attributes)
                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

        #folders 
        artIIIId = blackboard.getOrAddArtifactType("TSK_FOLDERS", "Folders")
        
        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db" )
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the folders table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT foldername, last_sync, basepath FROM folders")
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    foldername = resultSet.getString("foldername")
                    last_sync = resultSet.getLong("last_sync")
                    basepath = resultSet.getString("basepath")
                    
                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")                
                
                # Make an artifact on the blackboard, TSK_DOWNLOAD_SOURCE and give it attributes for each of the fields
                art = file.newArtifact(artIIIId.getTypeID())
                
                folder_name_att_type = blackboard.getOrAddAttributeType('BMW_FOLDER_NAME_TYPE',BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "foldername")
                
                attributes = ArrayList()
                
                attributes.add(BlackboardAttribute(folder_name_att_type,IviBmwDbIngestModuleFactory.moduleName, foldername)) 
                timevalue = last_sync/1000000000
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_MODIFIED.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, timevalue))
                attributes.add(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PATH.getTypeID(), IviBmwDbIngestModuleFactory.moduleName, basepath))

                art.addAttributes(attributes)
                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())
                
        #Library albuns        
        artIIIIId = blackboard.getOrAddArtifactType("TSK_LIBRARY_ALBUNS", "Library albums")

        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db" )
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the Library albuns table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT library_albums.album FROM library_albums")
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    album = resultSet.getString("album")
                    
                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")                
                
                # Make an artifact on the blackboard, TSK_DOWNLOAD_SOURCE and give it attributes for each of the fields
                art = file.newArtifact(artIIIIId.getTypeID())
                library_albums_att_type = blackboard.getOrAddAttributeType('BMW_LIBRARY_ALBUMS_TYPE',BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "album")
                attributes = ArrayList()
                
                attributes.add(BlackboardAttribute(library_albums_att_type,IviBmwDbIngestModuleFactory.moduleName, album)) 

                art.addAttributes(attributes)
                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

        #Library artists        
        artIIIIIId = blackboard.getOrAddArtifactType("TSK_LIBRARY_ARTISTS", "Library artists")

        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + file.getName())
            fileCount += 1

            # Save the DB locally in the temp folder. use file id as name to reduce collisions
            lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getId()) + ".db" )
            ContentUtils.writeToFile(file, File(lclDbPath))
                        
            # Open the DB using JDBC
            try: 
                Class.forName("org.sqlite.JDBC").newInstance()
                dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
            except SQLException as e:
                self.log(Level.INFO, "Could not open database file (not SQLite) " + file.getName() + " (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK
            
            # Query the Library artists  table in the database and get all columns. 
            try:
                stmt = dbConn.createStatement()
                resultSet = stmt.executeQuery("SELECT library_artists.artist FROM library_artists")
            except SQLException as e:
                self.log(Level.INFO, "Error querying database for contacts table (" + e.getMessage() + ")")
                return IngestModule.ProcessResult.OK

            # Cycle through each row and create artifacts
            while resultSet.next():
                try: 
                    artist = resultSet.getString("artist")
                    
                    
                except SQLException as e:
                    self.log(Level.INFO, "Error getting values from contacts table (" + e.getMessage() + ")")                
                
                # Make an artifact on the blackboard, TSK_DOWNLOAD_SOURCE and give it attributes for each of the fields
                art = file.newArtifact(artIIIIIId.getTypeID())
                library_artists_att_type = blackboard.getOrAddAttributeType('BMW_LIBRARY_ARTISTS_TYPE',BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "artist")
                attributes = ArrayList()
                
                attributes.add(BlackboardAttribute(library_artists_att_type,IviBmwDbIngestModuleFactory.moduleName, artist)) 

                art.addAttributes(attributes)
                try:
                    # index the artifact for keyword search
                    blackboard.indexArtifact(art)
                except Blackboard.BlackboardException as e:
                    self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

        #Post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Sample Jython Data Source Ingest Module", "Found %d files" % fileCount)
        IngestServices.getInstance().postMessage(message)
        
        return IngestModule.ProcessResult.OK
