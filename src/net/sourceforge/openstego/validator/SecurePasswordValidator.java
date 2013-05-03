package net.sourceforge.openstego.validator;

import edu.vt.middleware.password.*;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Lukasz Piliszczuk <lukasz.pili AT gmail.com>
 */
public class SecurePasswordValidator {

    private PasswordValidator passwordValidator;

    public SecurePasswordValidator() {

        LengthRule lengthRule = new LengthRule(8, 16);
        WhitespaceRule whitespaceRule = new WhitespaceRule();

        CharacterCharacteristicsRule charRule = new CharacterCharacteristicsRule();
        charRule.getRules().add(new DigitCharacterRule(1));
        charRule.getRules().add(new UppercaseCharacterRule(1));
        charRule.getRules().add(new LowercaseCharacterRule(1));
        charRule.setNumberOfCharacteristics(3);

        AlphabeticalSequenceRule alphaSeqRule = new AlphabeticalSequenceRule();
        NumericalSequenceRule numSeqRule = new NumericalSequenceRule();
        QwertySequenceRule qwertySeqRule = new QwertySequenceRule();

        List<Rule> ruleList = new ArrayList<Rule>();
        ruleList.add(lengthRule);
        ruleList.add(whitespaceRule);
        ruleList.add(charRule);
        ruleList.add(alphaSeqRule);
        ruleList.add(numSeqRule);
        ruleList.add(qwertySeqRule);

        passwordValidator = new PasswordValidator(ruleList);
    }

    public boolean isValid(String password) {
        PasswordData passwordData = new PasswordData(new Password(password));
        RuleResult result = passwordValidator.validate(passwordData);

        return result.isValid();
    }
}
