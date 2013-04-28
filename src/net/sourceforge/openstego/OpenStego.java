/*
 * Steganography utility to hide messages into cover files
 * Author: Samir Vaidya (mailto:syvaidya@gmail.com)
 * Copyright (c) 2007-2008 Samir Vaidya
 */

package net.sourceforge.openstego;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import javax.swing.UIManager;

import net.sourceforge.openstego.ui.OpenStegoUI;
import net.sourceforge.openstego.util.CmdLineOption;
import net.sourceforge.openstego.util.CmdLineOptions;
import net.sourceforge.openstego.util.CmdLineParser;
import net.sourceforge.openstego.util.CommonUtil;
import net.sourceforge.openstego.util.LabelUtil;
import net.sourceforge.openstego.util.PasswordInput;
import net.sourceforge.openstego.util.PluginManager;

/**
 * This is the main class for OpenStego. It includes the {@link #main(String[])} method which provides the
 * command line interface for the tool. It also has API methods which can be used by external programs
 * when using OpenStego as a library.
 */
public class OpenStego {
    /**
     * Constant for the namespace for labels
     */
    public static final String NAMESPACE = "OpenStego";

    /**
     * LabelUtil instance to retrieve labels
     */
    private static LabelUtil labelUtil = LabelUtil.getInstance(NAMESPACE);

    /**
     * Configuration data
     */
    private OpenStegoConfig config = null;

    /**
     * Stego plugin to use for embedding / extracting data
     */
    private OpenStegoPlugin plugin = null;

    /**
     * Flag to indicate whether plugin to be used is explicitly provided or not
     */
    private boolean isPluginExplicit = false;

    static {
        LabelUtil.addNamespace(NAMESPACE, "net.sourceforge.openstego.resource.OpenStegoLabels");
    }

    /**
     * Constructor using the default configuration
     *
     * @param plugin Stego plugin to use
     * @throws OpenStegoException
     */
    public OpenStego(OpenStegoPlugin plugin) throws OpenStegoException {
        this(plugin, (OpenStegoConfig) null);
    }

    /**
     * Constructor using <code>OpenStegoConfig</code> object
     *
     * @param plugin Stego plugin to use
     * @param config OpenStegoConfig object with configuration data
     * @throws OpenStegoException
     */
    public OpenStego(OpenStegoPlugin plugin, OpenStegoConfig config) throws OpenStegoException {
        if (plugin == null) {
            this.plugin = PluginManager.getDefaultPlugin();
            this.isPluginExplicit = false;
        } else {
            this.plugin = plugin;
            this.isPluginExplicit = true;
        }

        if (config == null) {
            this.config = this.plugin.createConfig();
        } else {
            this.config = config;
        }
    }

    /**
     * Constructor with configuration data in the form of <code>Map<code>
     *
     * @param plugin  Plugin object
     * @param propMap Map containing the configuration data
     * @throws OpenStegoException
     */
    public OpenStego(OpenStegoPlugin plugin, Map propMap) throws OpenStegoException {
        this(plugin, new OpenStegoConfig(propMap));
    }

    /**
     * Method to embed the message data into the cover data
     *
     * @param msg           Message data to be embedded
     * @param msgFileName   Name of the message file
     * @param cover         Cover data into which message data needs to be embedded
     * @param coverFileName Name of the cover file
     * @param stegoFileName Name of the output stego file
     * @return Stego data containing the embedded message
     * @throws OpenStegoException
     */
    public byte[] embedData(byte[] msg, String msgFileName, byte[] cover, String coverFileName, String stegoFileName)
            throws OpenStegoException {
        try {
            // Compress data, if requested
            if (config.isUseCompression()) {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                GZIPOutputStream zos = new GZIPOutputStream(bos);
                zos.write(msg);
                zos.finish();
                zos.close();
                bos.close();

                msg = bos.toByteArray();
            }

            // Encrypt data, if requested
            if (config.isUseEncryption()) {
                OpenStegoCrypto crypto = new OpenStegoCrypto(config.getPassword(), config.getCryptoAlgorithm());
                msg = crypto.encrypt(msg);
            }

            return plugin.embedData(msg, msgFileName, cover, coverFileName, stegoFileName);
        } catch (OpenStegoException osEx) {
            throw osEx;
        } catch (Exception ex) {
            throw new OpenStegoException(ex);
        }
    }

    /**
     * Method to embed the message data into the cover data (alternate API)
     *
     * @param msgFile       File containing the message data to be embedded
     * @param coverFile     Cover file into which data needs to be embedded
     * @param stegoFileName Name of the output stego file
     * @return Stego data containing the embedded message
     * @throws OpenStegoException
     */
    public byte[] embedData(File msgFile, File coverFile, String stegoFileName) throws OpenStegoException {
        InputStream is = null;
        String filename = null;

        try {
            // If no message file is provided, then read the data from stdin
            if (msgFile == null) {
                is = System.in;
            } else {
                is = new FileInputStream(msgFile);
                filename = msgFile.getName();
            }

            return embedData(CommonUtil.getStreamBytes(is), filename, coverFile == null ? null : CommonUtil
                    .getFileBytes(coverFile), coverFile == null ? null : coverFile.getName(), stegoFileName);
        } catch (IOException ioEx) {
            throw new OpenStegoException(ioEx);
        }
    }

    /**
     * Method to embed the watermark signature data into the cover data
     *
     * @param sig           Signature data to be embedded
     * @param sigFileName   Name of the signature file
     * @param cover         Cover data into which signature data needs to be embedded
     * @param coverFileName Name of the cover file
     * @param stegoFileName Name of the output stego file
     * @return Stego data containing the embedded signature
     * @throws OpenStegoException
     */
    public byte[] embedMark(byte[] sig, String sigFileName, byte[] cover, String coverFileName, String stegoFileName)
            throws OpenStegoException {
        try {
            // No compression and encryption should be done as this is signature data

            return plugin.embedData(sig, sigFileName, cover, coverFileName, stegoFileName);
        } catch (OpenStegoException osEx) {
            throw osEx;
        } catch (Exception ex) {
            throw new OpenStegoException(ex);
        }
    }

    /**
     * Method to embed the watermark signature data into the cover data (alternate API)
     *
     * @param sigFile       File containing the signature data to be embedded
     * @param coverFile     Cover file into which data needs to be embedded
     * @param stegoFileName Name of the output stego file
     * @return Stego data containing the embedded signature
     * @throws OpenStegoException
     */
    public byte[] embedMark(File sigFile, File coverFile, String stegoFileName) throws OpenStegoException {
        InputStream is = null;
        String filename = null;

        try {
            // If no signature file is provided, then read the data from stdin
            if (sigFile == null) {
                is = System.in;
            } else {
                is = new FileInputStream(sigFile);
                filename = sigFile.getName();
            }

            return embedMark(CommonUtil.getStreamBytes(is), filename, coverFile == null ? null : CommonUtil
                    .getFileBytes(coverFile), coverFile == null ? null : coverFile.getName(), stegoFileName);
        } catch (IOException ioEx) {
            throw new OpenStegoException(ioEx);
        }
    }

    /**
     * Method to extract the message data from stego data
     *
     * @param stegoData     Stego data from which the message needs to be extracted
     * @param stegoFileName Name of the stego file
     * @return Extracted message (List's first element is filename and second element is the message as byte array)
     * @throws OpenStegoException
     */
    public List extractData(byte[] stegoData, String stegoFileName) throws OpenStegoException {
        byte[] msg = null;
        List output = new ArrayList();
        List pluginList = null;
        boolean pluginFound = false;
        OpenStegoConfig tempConfig = null;

        try {
            // If plugin is not specified explicitly, then determine the plugin to use
            if (!isPluginExplicit) {
                pluginFound = false;
                pluginList = PluginManager.getPlugins();

                for (int i = 0; i < pluginList.size(); i++) {
                    plugin = (OpenStegoPlugin) pluginList.get(i);
                    tempConfig = plugin.createConfig();
                    tempConfig.setPassword(config.getPassword());
                    config = tempConfig;
                    if (plugin.canHandle(stegoData)) {
                        pluginFound = true;
                        break;
                    }
                }

                if (!pluginFound) {
                    throw new OpenStegoException(OpenStego.NAMESPACE, OpenStegoException.NO_VALID_PLUGIN, null);
                }
            }

            // Add file name as first element of output list
            output.add(plugin.extractMsgFileName(stegoData, stegoFileName));
            msg = plugin.extractData(stegoData, stegoFileName, null);

            // Decrypt data, if required
            if (config.isUseEncryption()) {
                OpenStegoCrypto crypto = new OpenStegoCrypto(config.getPassword(), config.getCryptoAlgorithm());
                msg = crypto.decrypt(msg);
            }

            // Decompress data, if required
            if (config.isUseCompression()) {
                try {
                    ByteArrayInputStream bis = new ByteArrayInputStream(msg);
                    GZIPInputStream zis = new GZIPInputStream(bis);
                    msg = CommonUtil.getStreamBytes(zis);
                    zis.close();
                    bis.close();
                } catch (IOException ioEx) {
                    throw new OpenStegoException(OpenStego.NAMESPACE, OpenStegoException.CORRUPT_DATA, ioEx);
                }
            }

            // Add message as second element of output list
            output.add(msg);
        } catch (OpenStegoException osEx) {
            throw osEx;
        } catch (Exception ex) {
            throw new OpenStegoException(ex);
        }

        return output;
    }

    /**
     * Method to extract the message data from stego data (alternate API)
     *
     * @param stegoFile Stego file from which message needs to be extracted
     * @return Extracted message (List's first element is filename and second element is the message as byte array)
     * @throws OpenStegoException
     */
    public List extractData(File stegoFile) throws OpenStegoException {
        return extractData(CommonUtil.getFileBytes(stegoFile), stegoFile.getName());
    }

    /**
     * Method to extract the watermark data from stego data
     *
     * @param stegoData     Stego data from which the watermark needs to be extracted
     * @param stegoFileName Name of the stego file
     * @param origSigData   Original signature data
     * @return Extracted watermark
     * @throws OpenStegoException
     */
    public byte[] extractMark(byte[] stegoData, String stegoFileName, byte[] origSigData) throws OpenStegoException {
        // Plugin is mandatory
        if (!isPluginExplicit) {
            throw new OpenStegoException(NAMESPACE, OpenStegoException.NO_PLUGIN_SPECIFIED, null);
        }

        return plugin.extractData(stegoData, stegoFileName, origSigData);
    }

    /**
     * Method to extract the watermark data from stego data (alternate API)
     *
     * @param stegoFile   Stego file from which watermark needs to be extracted
     * @param origSigFile Original signature file
     * @return Extracted watermark
     * @throws OpenStegoException
     */
    public byte[] extractMark(File stegoFile, File origSigFile) throws OpenStegoException {
        return extractMark(CommonUtil.getFileBytes(stegoFile), stegoFile.getName(), CommonUtil
                .getFileBytes(origSigFile));
    }

    /**
     * Method to check the correlation for the given image and the original signature
     *
     * @param stegoData     Stego data containing the watermark
     * @param stegoFileName Name of the stego file
     * @param origSigData   Original signature data
     * @return Correlation
     * @throws OpenStegoException
     */
    public double checkMark(byte[] stegoData, String stegoFileName, byte[] origSigData) throws OpenStegoException {
        // Plugin is mandatory
        if (!isPluginExplicit) {
            throw new OpenStegoException(NAMESPACE, OpenStegoException.NO_PLUGIN_SPECIFIED, null);
        }

        return plugin.checkMark(stegoData, stegoFileName, origSigData);
    }

    /**
     * Method to check the correlation for the given image and the original signature (alternate API)
     *
     * @param stegoFile   Stego file from which watermark needs to be extracted
     * @param origSigFile Original signature file
     * @return Correlation
     * @throws OpenStegoException
     */
    public double checkMark(File stegoFile, File origSigFile) throws OpenStegoException {
        return checkMark(CommonUtil.getFileBytes(stegoFile), stegoFile.getName(), CommonUtil.getFileBytes(origSigFile));
    }

    /**
     * Method to generate the signature data using the given plugin
     *
     * @return Signature data
     * @throws OpenStegoException
     */
    public byte[] generateSignature() throws OpenStegoException {
        try {
            if (!isPluginExplicit) {
                throw new OpenStegoException(OpenStego.NAMESPACE, OpenStegoException.NO_PLUGIN_SPECIFIED, null);
            }
            if (!plugin.getPurposes().contains(OpenStegoPlugin.PURPOSE_WATERMARKING)) {
                throw new OpenStegoException(OpenStego.NAMESPACE, OpenStegoException.SIG_NA_PLUGIN_NOT_WM, null);
            }
            return plugin.generateSignature();
        } catch (OpenStegoException osEx) {
            throw osEx;
        } catch (Exception ex) {
            throw new OpenStegoException(ex);
        }
    }

    /**
     * Method to get difference between original cover file and the stegged file
     *
     * @param stegoData     Stego data containing the embedded data
     * @param stegoFileName Name of the stego file
     * @param coverData     Original cover data
     * @param coverFileName Name of the cover file
     * @param diffFileName  Name of the output difference file
     * @return Difference data
     * @throws OpenStegoException
     */
    public byte[] getDiff(byte[] stegoData, String stegoFileName, byte[] coverData, String coverFileName,
                          String diffFileName) throws OpenStegoException {
        // Plugin is mandatory
        if (!isPluginExplicit) {
            throw new OpenStegoException(NAMESPACE, OpenStegoException.NO_PLUGIN_SPECIFIED, null);
        }

        return plugin.getDiff(stegoData, stegoFileName, coverData, coverFileName, diffFileName);
    }

    /**
     * Method to get difference between original cover file and the stegged file
     *
     * @param stegoFile    Stego file containing the embedded data
     * @param coverFile    Original cover file
     * @param diffFileName Name of the output difference file
     * @return Difference data
     * @throws OpenStegoException
     */
    public byte[] getDiff(File stegoFile, File coverFile, String diffFileName) throws OpenStegoException {
        return getDiff(CommonUtil.getFileBytes(stegoFile), stegoFile.getName(), CommonUtil.getFileBytes(coverFile),
                coverFile.getName(), diffFileName);
    }

    /**
     * Get method for configuration data
     *
     * @return Configuration data
     */
    public OpenStegoConfig getConfig() {
        return config;
    }

    /**
     * Main method for calling openstego from command line.
     *
     * @param args Command line arguments
     */
    public static void main(String[] args) {
        String msgFileName = null;
        String sigFileName = null;
        String coverFileName = null;
        String stegoFileName = null;
        String extractDir = null;
        String extractFileName = null;
        String signatureFileName = null;
        String command = null;
        String pluginName = null;
        List msgData = null;
        List coverFileList = null;
        List stegoFileList = null;
        OpenStego stego = null;
        CmdLineParser parser = null;
        CmdLineOptions options = null;
        CmdLineOption option = null;
        List optionList = null;
        OpenStegoPlugin plugin = null;

        try {
            // First parse of the command-line (without plugin specific options)
            parser = new CmdLineParser(getStdCmdLineOptions(null), args);
            if (!parser.isValid()) {
                displayUsage();
                return;
            }

            // Load the stego plugins
            PluginManager.loadPlugins();

            if (parser.getNumOfOptions() == 0) // Start GUI
            {
                try {
                    UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
                } catch (Exception e) {
                }
                new OpenStegoUI().setVisible(true);
            } else {
                pluginName = parser.getParsedOptions().getOptionValue("-a");

                // Get the plugin object, and refresh the command-line parser data
                if (pluginName != null && !pluginName.equals("")) {
                    plugin = PluginManager.getPluginByName(pluginName);
                    if (plugin == null) {
                        throw new OpenStegoException(NAMESPACE, OpenStegoException.PLUGIN_NOT_FOUND, pluginName, null);
                    }
                }
                // Functionality for Auto-select of plugin is removed
                /*else
                {
                    plugin = PluginManager.getDefaultPlugin();
                }*/

                // Second parse of the command-line (with plugin specific options)
                if (plugin != null) {
                    parser = new CmdLineParser(getStdCmdLineOptions(plugin), args);
                }

                optionList = parser.getParsedOptionsAsList();
                options = parser.getParsedOptions();

                for (int i = 0; i < optionList.size(); i++) {
                    option = (CmdLineOption) optionList.get(i);
                    if (((i == 0) && (option.getType() != CmdLineOption.TYPE_COMMAND))
                            || ((i > 0) && (option.getType() == CmdLineOption.TYPE_COMMAND))) {
                        displayUsage();
                        return;
                    }

                    if (i == 0) {
                        command = option.getName();
                    }
                }

                // Non-standard options are not allowed
                if (parser.getNonStdOptions().size() > 0) {
                    displayUsage();
                    return;
                }

                // Check that algorithm is selected
                if (!command.equals("help") && !command.equals("diff") && !command.equals("algorithms")
                        && plugin == null) {
                    throw new OpenStegoException(NAMESPACE, OpenStegoException.NO_PLUGIN_SPECIFIED, null);
                }

                // Create main stego object
                stego = new OpenStego((pluginName != null && !pluginName.equals("")) ? plugin : null, plugin
                        .createConfig(parser.getParsedOptions()));

                if (command.equals("embed")) {
                    msgFileName = options.getOptionValue("-mf");
                    coverFileName = options.getOptionValue("-cf");
                    stegoFileName = options.getOptionValue("-sf");

                    // Check if we need to prompt for password
                    if (stego.getConfig().isUseEncryption() && stego.getConfig().getPassword() == null) {
                        stego.getConfig().setPassword(
                                PasswordInput.readPassword(labelUtil.getString("cmd.msg.enterPassword") + " "));
                    }

                    coverFileList = CommonUtil.parseFileList(coverFileName, ";");
                    // If no coverfile or only one coverfile is provided then use stegofile name given by the user
                    if (coverFileList.size() <= 1) {
                        if (coverFileList.size() == 0 && coverFileName != null && !coverFileName.equals("-")) {
                            System.err.println(labelUtil.getString("cmd.msg.coverFileNotFound",
                                    new Object[]{coverFileName}));
                            return;
                        }

                        CommonUtil.writeFile(stego.embedData((msgFileName == null || msgFileName.equals("-")) ? null
                                : new File(msgFileName),
                                coverFileList.size() == 0 ? null : (File) coverFileList.get(0),
                                (stegoFileName == null || stegoFileName.equals("-")) ? null : stegoFileName),
                                (stegoFileName == null || stegoFileName.equals("-")) ? null : stegoFileName);
                    }
                    // Else loop through all coverfiles and overwrite the same coverfiles with generated stegofiles
                    else {
                        // If stego file name is provided, then warn user that it will be ignored
                        if (stegoFileName != null && !stegoFileName.equals("-")) {
                            System.err.println(labelUtil.getString("cmd.warn.stegoFileIgnored"));
                        }

                        // Loop through all cover files
                        for (int i = 0; i < coverFileList.size(); i++) {
                            coverFileName = ((File) coverFileList.get(i)).getName();
                            CommonUtil.writeFile(stego.embedData(
                                    (msgFileName == null || msgFileName.equals("-")) ? null : new File(msgFileName),
                                    (File) coverFileList.get(i), coverFileName), coverFileName);

                            System.err.println(labelUtil.getString("cmd.msg.coverProcessed",
                                    new Object[]{coverFileName}));
                        }
                    }
                } else if (command.equals("embedmark")) {
                    sigFileName = options.getOptionValue("-gf");
                    coverFileName = options.getOptionValue("-cf");
                    stegoFileName = options.getOptionValue("-sf");

                    coverFileList = CommonUtil.parseFileList(coverFileName, ";");
                    // If no coverfile or only one coverfile is provided then use stegofile name given by the user
                    if (coverFileList.size() <= 1) {
                        if (coverFileList.size() == 0 && coverFileName != null && !coverFileName.equals("-")) {
                            System.err.println(labelUtil.getString("cmd.msg.coverFileNotFound",
                                    new Object[]{coverFileName}));
                            return;
                        }

                        CommonUtil.writeFile(stego.embedMark((sigFileName == null || sigFileName.equals("-")) ? null
                                : new File(sigFileName),
                                coverFileList.size() == 0 ? null : (File) coverFileList.get(0),
                                (stegoFileName == null || stegoFileName.equals("-")) ? null : stegoFileName),
                                (stegoFileName == null || stegoFileName.equals("-")) ? null : stegoFileName);
                    }
                    // Else loop through all coverfiles and overwrite the same coverfiles with generated stegofiles
                    else {
                        // If stego file name is provided, then warn user that it will be ignored
                        if (stegoFileName != null && !stegoFileName.equals("-")) {
                            System.err.println(labelUtil.getString("cmd.warn.stegoFileIgnored"));
                        }

                        // Loop through all cover files
                        for (int i = 0; i < coverFileList.size(); i++) {
                            coverFileName = ((File) coverFileList.get(i)).getName();
                            CommonUtil.writeFile(stego.embedMark(
                                    (sigFileName == null || sigFileName.equals("-")) ? null : new File(sigFileName),
                                    (File) coverFileList.get(i), coverFileName), coverFileName);

                            System.err.println(labelUtil.getString("cmd.msg.coverProcessed",
                                    new Object[]{coverFileName}));
                        }
                    }
                } else if (command.equals("extract")) {
                    stegoFileName = options.getOptionValue("-sf");
                    extractDir = options.getOptionValue("-xd");

                    if (stegoFileName == null) {
                        displayUsage();
                        return;
                    }

                    try {
                        msgData = stego.extractData(new File(stegoFileName));
                    } catch (OpenStegoException osEx) {
                        if (osEx.getErrorCode() == OpenStegoException.INVALID_PASSWORD) {
                            if (stego.getConfig().getPassword() == null) {
                                stego.getConfig().setPassword(
                                        PasswordInput.readPassword(labelUtil.getString("cmd.msg.enterPassword") + " "));

                                try {
                                    msgData = stego.extractData(new File(stegoFileName));
                                } catch (OpenStegoException inEx) {
                                    if (inEx.getErrorCode() == OpenStegoException.INVALID_PASSWORD) {
                                        System.err.println(inEx.getMessage());
                                        return;
                                    } else {
                                        throw inEx;
                                    }
                                }
                            } else {
                                System.err.println(osEx.getMessage());
                                return;
                            }
                        } else {
                            throw osEx;
                        }
                    }
                    extractFileName = options.getOptionValue("-xf");
                    if (extractFileName == null) {
                        extractFileName = (String) msgData.get(0);
                        if (extractFileName == null || extractFileName.equals("")) {
                            extractFileName = "untitled";
                        }
                    }
                    if (extractDir != null) {
                        extractFileName = extractDir + File.separator + extractFileName;
                    }

                    CommonUtil.writeFile((byte[]) msgData.get(1), extractFileName);
                    System.err.println(labelUtil.getString("cmd.msg.fileExtracted", new Object[]{extractFileName}));
                } else if (command.equals("extractmark")) {
                    stegoFileName = options.getOptionValue("-sf");
                    sigFileName = options.getOptionValue("-gf");
                    extractDir = options.getOptionValue("-xd");
                    extractFileName = options.getOptionValue("-xf");

                    if (stegoFileName == null || extractFileName == null) {
                        displayUsage();
                        return;
                    }

                    if (extractDir != null) {
                        extractFileName = extractDir + File.separator + extractFileName;
                    }

                    CommonUtil.writeFile(stego.extractMark(new File(stegoFileName), new File(sigFileName)),
                            extractFileName);
                } else if (command.equals("checkmark")) {
                    stegoFileName = options.getOptionValue("-sf");
                    sigFileName = options.getOptionValue("-gf");

                    if (stegoFileName == null || sigFileName == null) {
                        displayUsage();
                        return;
                    }

                    stegoFileList = CommonUtil.parseFileList(stegoFileName, ";");
                    // If only one stegofile is provided then use stegofile name given by the user
                    if (stegoFileList.size() == 1) {
                        System.out.println(stego.checkMark((File) stegoFileList.get(0), new File(sigFileName)));
                    }
                    // Else loop through all stegofiles and calculate correlation value for each
                    else {
                        for (int i = 0; i < stegoFileList.size(); i++) {
                            stegoFileName = ((File) stegoFileList.get(i)).getName();
                            System.out.println(stegoFileName + ": "
                                    + stego.checkMark((File) stegoFileList.get(i), new File(sigFileName)));
                        }
                    }
                } else if (command.equals("gensig")) {
                    signatureFileName = options.getOptionValue("-gf");
                    CommonUtil.writeFile(stego.generateSignature(), (signatureFileName == null || signatureFileName
                            .equals("-")) ? null : signatureFileName);
                } else if (command.equals("diff")) {
                    coverFileName = options.getOptionValue("-cf");
                    stegoFileName = options.getOptionValue("-sf");
                    extractDir = options.getOptionValue("-xd");
                    extractFileName = options.getOptionValue("-xf");

                    if (extractDir != null) {
                        extractFileName = extractDir + File.separator + extractFileName;
                    }

                    CommonUtil.writeFile(stego.getDiff(new File(stegoFileName), new File(coverFileName),
                            extractFileName), extractFileName);
                } else if (command.equals("readformats")) {
                    List formats = plugin.getReadableFileExtensions();
                    for (int i = 0; i < formats.size(); i++) {
                        System.out.println(formats.get(i));
                    }
                } else if (command.equals("writeformats")) {
                    List formats = plugin.getWritableFileExtensions();
                    for (int i = 0; i < formats.size(); i++) {
                        System.out.println(formats.get(i));
                    }
                } else if (command.equals("algorithms")) {
                    List plugins = PluginManager.getPlugins();
                    for (int i = 0; i < plugins.size(); i++) {
                        plugin = (OpenStegoPlugin) plugins.get(i);
                        System.out.println(plugin.getName() + " " + plugin.getPurposesLabel() + " - "
                                + plugin.getDescription());
                    }
                } else if (command.equals("help")) {
                    if (plugin == null) {
                        displayUsage();
                        return;
                    } else
                    // Show plugin-specific help
                    {
                        System.err.println(plugin.getUsage());
                    }
                } else {
                    displayUsage();
                    return;
                }
            }
        } catch (OpenStegoException osEx) {
            if (osEx.getErrorCode() == 0) {
                osEx.printStackTrace();
            } else {
                System.err.println(osEx.getMessage());
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    /**
     * Method to display usage for OpenStego
     *
     * @throws OpenStegoException
     */
    private static void displayUsage() throws OpenStegoException {
        PluginManager.loadPlugins();

        System.err.print(labelUtil.getString("versionString"));
        System.err.println(labelUtil.getString("cmd.usage", new Object[]{File.separator,
                PluginManager.getDefaultPlugin().getName()}));
    }

    /**
     * Method to generate the standard list of command-line options
     *
     * @param plugin Stego plugin for plugin-specific command-line options
     * @return Standard list of command-line options
     * @throws OpenStegoException
     */
    private static CmdLineOptions getStdCmdLineOptions(OpenStegoPlugin plugin) throws OpenStegoException {
        CmdLineOptions options = new CmdLineOptions();

        // Commands
        options.add("embed", "--embed", CmdLineOption.TYPE_COMMAND, false);
        options.add("extract", "--extract", CmdLineOption.TYPE_COMMAND, false);
        options.add("gensig", "--gensig", CmdLineOption.TYPE_COMMAND, false);
        options.add("embedmark", "--embedmark", CmdLineOption.TYPE_COMMAND, false);
        options.add("extractmark", "--extractmark", CmdLineOption.TYPE_COMMAND, false);
        options.add("checkmark", "--checkmark", CmdLineOption.TYPE_COMMAND, false);
        options.add("diff", "--diff", CmdLineOption.TYPE_COMMAND, false);
        options.add("readformats", "--readformats", CmdLineOption.TYPE_COMMAND, false);
        options.add("writeformats", "--writeformats", CmdLineOption.TYPE_COMMAND, false);
        options.add("algorithms", "--algorithms", CmdLineOption.TYPE_COMMAND, false);
        options.add("help", "--help", CmdLineOption.TYPE_COMMAND, false);

        // Plugin options
        options.add("-a", "--algorithm", CmdLineOption.TYPE_OPTION, true);

        // File options
        options.add("-mf", "--messagefile", CmdLineOption.TYPE_OPTION, true);
        options.add("-cf", "--coverfile", CmdLineOption.TYPE_OPTION, true);
        options.add("-sf", "--stegofile", CmdLineOption.TYPE_OPTION, true);
        options.add("-xf", "--extractfile", CmdLineOption.TYPE_OPTION, true);
        options.add("-xd", "--extractdir", CmdLineOption.TYPE_OPTION, true);
        options.add("-gf", "--sigfile", CmdLineOption.TYPE_OPTION, true);

        // Command options
        options.add("-c", "--compress", CmdLineOption.TYPE_OPTION, false);
        options.add("-C", "--nocompress", CmdLineOption.TYPE_OPTION, false);
        options.add("-e", "--encrypt", CmdLineOption.TYPE_OPTION, false);
        options.add("-E", "--noencrypt", CmdLineOption.TYPE_OPTION, false);
        options.add("-p", "--password", CmdLineOption.TYPE_OPTION, true);

        // Plugin-specific options
        if (plugin != null) {
            plugin.populateStdCmdLineOptions(options);
        }

        return options;
    }
}
