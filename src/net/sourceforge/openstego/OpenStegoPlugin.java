/*
 * Steganography utility to hide messages into cover files
 * Author: Samir Vaidya (mailto:syvaidya@gmail.com)
 * Copyright (c) 2007-2008 Samir Vaidya
 */

package net.sourceforge.openstego;

import java.lang.reflect.Constructor;
import java.util.List;
import java.util.Map;

import net.sourceforge.openstego.ui.OpenStegoUI;
import net.sourceforge.openstego.ui.PluginEmbedOptionsUI;
import net.sourceforge.openstego.util.CmdLineOptions;
import net.sourceforge.openstego.util.LabelUtil;

/**
 * Abstract class for stego plugins for OpenStego. Abstract methods need to be implemented to add support for more
 * steganographic algorithms
 */
public abstract class OpenStegoPlugin
{
    /**
     * Constant for the purpose of the plugin - Data Hiding
     */
    public static final String PURPOSE_DATA_HIDING = "DH";

    /**
     * Constant for the purpose of the plugin - Watermarking
     */
    public static final String PURPOSE_WATERMARKING = "WM";

    /**
     * Configuration data to be used while embedding / extracting data
     */
    protected OpenStegoConfig config = null;

    // ------------- Metadata Methods -------------

    /**
     * Gives the name of the plugin
     * @return Name of the plugin
     */
    public abstract String getName();

    /**
     * Gives the purpose(s) of the plugin
     * @return Purpose(s) of the plugin
     */
    public abstract List getPurposes();

    /**
     * Gives a short description of the plugin
     * @return Short description of the plugin
     */
    public abstract String getDescription();

    /**
     * Gives the display label for purpose(s) of the plugin
     * @return Display lable for purpose(s) of the plugin
     */
    public final String getPurposesLabel()
    {
        StringBuffer sbf = new StringBuffer();
        LabelUtil labelUtil = LabelUtil.getInstance(OpenStego.NAMESPACE);
        List purposes = getPurposes();

        if(purposes == null || purposes.size() == 0)
        {
            return "";
        }

        sbf.append("(").append(labelUtil.getString("cmd.label.purpose.caption")).append(" ");
        for(int i = 0; i < purposes.size(); i++)
        {
            if(i > 0)
            {
                sbf.append(", ");
            }
            sbf.append(labelUtil.getString("cmd.label.purpose." + purposes.get(i)));
        }
        sbf.append(")");

        return sbf.toString();
    }

    // ------------- Core Stego Methods -------------

    /**
     * Method to embed the message into the cover data
     * @param msg Message to be embedded
     * @param msgFileName Name of the message file. If this value is provided, then the filename should be embedded in
     *            the cover data
     * @param cover Cover data into which message needs to be embedded
     * @param coverFileName Name of the cover file
     * @param stegoFileName Name of the output stego file
     * @return Stego data containing the message
     * @throws net.sourceforge.openstego.OpenStegoException
     */
    public abstract byte[] embedData(byte[] msg, String msgFileName, byte[] cover, String coverFileName,
            String stegoFileName) throws OpenStegoException;

    /**
     * Method to extract the message file name from the stego data
     * @param stegoData Stego data containing the message
     * @param stegoFileName Name of the stego file
     * @return Message file name
     * @throws net.sourceforge.openstego.OpenStegoException
     */
    public abstract String extractMsgFileName(byte[] stegoData, String stegoFileName) throws OpenStegoException;

    /**
     * Method to extract the message from the stego data
     * @param stegoData Stego data containing the message
     * @param stegoFileName Name of the stego file
     * @param origSigData Optional signature data file for watermark
     * @return Extracted message
     * @throws net.sourceforge.openstego.OpenStegoException
     */
    public abstract byte[] extractData(byte[] stegoData, String stegoFileName, byte[] origSigData)
            throws OpenStegoException;

    /**
     * Method to generate the signature data. This method needs to be implemented only if the purpose of the plugin is
     * Watermarking
     * @return Signature data
     * @throws net.sourceforge.openstego.OpenStegoException
     */
    public abstract byte[] generateSignature() throws OpenStegoException;

    /**
     * Method to check the correlation for the given image and the original signature
     * @param stegoData Stego data containing the watermark
     * @param stegoFileName Name of the stego file
     * @param origSigData Original signature data
     * @return Correlation
     * @throws net.sourceforge.openstego.OpenStegoException
     */
    public final double checkMark(byte[] stegoData, String stegoFileName, byte[] origSigData) throws OpenStegoException
    {
        return getWatermarkCorrelation(origSigData, extractData(stegoData, stegoFileName, origSigData));
    }

    /**
     * Method to check the correlation between original signature and the extracted watermark
     * @param origSigData Original signature data
     * @param watermarkData Extracted watermark data
     * @return Correlation
     * @throws net.sourceforge.openstego.OpenStegoException
     */
    public abstract double getWatermarkCorrelation(byte[] origSigData, byte[] watermarkData) throws OpenStegoException;

    /**
     * Method to get difference between original cover file and the stegged file
     * @param stegoData Stego data containing the embedded data
     * @param stegoFileName Name of the stego file
     * @param coverData Original cover data
     * @param coverFileName Name of the cover file
     * @param diffFileName Name of the output difference file
     * @return Difference data
     * @throws net.sourceforge.openstego.OpenStegoException
     */
    public abstract byte[] getDiff(byte[] stegoData, String stegoFileName, byte[] coverData, String coverFileName,
            String diffFileName) throws OpenStegoException;

    /**
     * Method to find out whether given stego data can be handled by this plugin or not
     * @param stegoData Stego data containing the message
     * @return Boolean indicating whether the stego data can be handled by this plugin or not
     */
    public abstract boolean canHandle(byte[] stegoData);

    /**
     * Method to get the list of supported file extensions for reading
     * @return List of supported file extensions for reading
     * @throws net.sourceforge.openstego.OpenStegoException
     */
    public abstract List getReadableFileExtensions() throws OpenStegoException;

    /**
     * Method to get the list of supported file extensions for writing
     * @return List of supported file extensions for writing
     * @throws net.sourceforge.openstego.OpenStegoException
     */
    public abstract List getWritableFileExtensions() throws OpenStegoException;

    // ------------- Command-line Related Methods -------------

    /**
     * Method to populate the standard command-line options used by this plugin
     * @param options Existing command-line options. Plugin-specific options will get added to this list
     * @throws net.sourceforge.openstego.OpenStegoException
     */
    public abstract void populateStdCmdLineOptions(CmdLineOptions options) throws OpenStegoException;

    /**
     * Method to get the usage details of the plugin
     * @return Usage details of the plugin
     * @throws net.sourceforge.openstego.OpenStegoException
     */
    public abstract String getUsage() throws OpenStegoException;

    // ------------- GUI Related Methods -------------

    /**
     * Method to get the UI object for "Embed" action specific to this plugin. This UI object will be embedded inside
     * the main OpenStego GUI
     * @param stegoUI Reference to the parent OpenStegoUI object
     * @return UI object specific to this plugin for "Embed" action
     * @throws net.sourceforge.openstego.OpenStegoException
     */
    public abstract PluginEmbedOptionsUI getEmbedOptionsUI(OpenStegoUI stegoUI) throws OpenStegoException;

    // ------------- Other Methods -------------

    /**
     * Method to get the configuration class specific to this plugin
     * @return Configuration class specific to this plugin
     */
    public abstract Class getConfigClass();

    /**
     * Method to create default configuration data (specific to this plugin)
     * @return Configuration data
     * @throws net.sourceforge.openstego.OpenStegoException
     */
    public final OpenStegoConfig createConfig() throws OpenStegoException
    {
        try
        {
            Constructor constructor = getConfigClass().getConstructor(new Class[0]);
            this.config = (OpenStegoConfig) constructor.newInstance(new Object[0]);
        }
        catch(Exception ex)
        {
            throw new OpenStegoException(ex);
        }
        return this.config;
    }

    /**
     * Method to create configuration data (specific to this plugin) based on the property map
     * @param propMap Property map
     * @return Configuration data
     * @throws net.sourceforge.openstego.OpenStegoException
     */
    public final OpenStegoConfig createConfig(Map propMap) throws OpenStegoException
    {
        try
        {
            Constructor constructor = getConfigClass().getConstructor(new Class[] { Map.class });
            this.config = (OpenStegoConfig) constructor.newInstance(new Object[] { propMap });
        }
        catch(Exception ex)
        {
            throw new OpenStegoException(ex);
        }
        return this.config;
    }

    /**
     * Method to create configuration data (specific to this plugin) based on the command-line options
     * @param options Command-line options
     * @return Configuration data
     * @throws net.sourceforge.openstego.OpenStegoException
     */
    public final OpenStegoConfig createConfig(CmdLineOptions options) throws OpenStegoException
    {
        try
        {
            Constructor constructor = getConfigClass().getConstructor(new Class[] { CmdLineOptions.class });
            this.config = (OpenStegoConfig) constructor.newInstance(new Object[] { options });
        }
        catch(Exception ex)
        {
            throw new OpenStegoException(ex);
        }
        return this.config;
    }

    /**
     * Get method for config
     * @return Configuration data
     */
    public final OpenStegoConfig getConfig()
    {
        return config;
    }
}