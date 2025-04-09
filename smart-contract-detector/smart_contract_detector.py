import os
import re
import sys
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.compose import ColumnTransformer
import joblib
import argparse
import json
import glob

class SmartContractVulnerabilityDetector:
    def __init__(self, smartbugs_repo_path=None):
        self.smartbugs_repo_path = smartbugs_repo_path
        self.model = None
        self.vectorizer = None
        self.feature_names = []
        # Fixed vulnerability patterns without problematic look-behind assertions
        self.vulnerability_patterns = {
            'reentrancy': r'(\.call\.value\s*\([^)]*\)\s*;|\.transfer\s*\([^)]*\)\s*;|\.send\s*\([^)]*\)\s*;)(?!.*(?:require|assert))',
            'timestamp_dependence': r'(now|block\.timestamp)(?=\s*[=<>!]+|\s+as|\s+\+|\s+-|\s*\*|\s*\/|\s*%|\s*\?)',
            'unchecked_send': r'(\.send\s*\([^)]*\)|\.transfer\s*\([^)]*\))(?![^;]*(?:require|assert|if))',
            'unprotected_functions': r'function\s+\w+\s*\([^)]*\)\s*(?:public|external)(?!\s+view|\s+pure|\s+constant)(?![^{]*(?:onlyOwner|require\s*\(\s*msg\.sender\s*==))',
            'tx_origin': r'tx\.origin(?=\s*[=<>!]+|\s+\|\||\s+&&|\s*\))',
            'integer_overflow': r'(\w+\s*\+\+|\w+\s*--|\w+\s*\+=|\w+\s*-=|\w+\s*\*=|\w+\s*\/=)(?![^;]*(?:SafeMath|require|assert|if))',
            'unchecked_math': r'(\w+\s*\+\s*\w+|\w+\s*-\s*\w+|\w+\s*\*\s*\w+|\w+\s*\/\s*\w+)(?![^;]*(?:SafeMath|require|assert|if))',
            'access_control': r'(onlyOwner|require\s*\(\s*msg\.sender\s*==)',
            'delegatecall': r'(\.delegatecall\s*\([^)]*\))(?![^;]*(?:require|assert|if))',
            'unchecked_low_level_calls': r'(\.call\s*\([^)]*\))(?![^;]*(?:require|assert|if))',
            'dos_vulnerable': r'(for\s*\([^;]*;\s*[^;]*;\s*[^)]*\)\s*{(?![^}]*(?:require|assert|if))|\bwhile\s*\([^)]*\)\s*{(?![^}]*(?:require|assert|if)))',
            'use_of_suicide': r'(suicide\s*\(|selfdestruct\s*\()',
        }
        
        # Security pattern indicators
        self.security_patterns = {
            'uses_safemath': r'using\s+SafeMath|contract\s+SafeMath|library\s+SafeMath',
            'uses_ownable': r'contract\s+Ownable|import\s+[\'"]Ownable[\'"]|is\s+Ownable',
            'uses_reentrancy_guard': r'ReentrancyGuard|nonReentrant|mutex',
            'uses_checks_effects_interactions': r'(?:\s*require\s*\([^;]*;\s*[^=]*\s*=\s*[^;]*;\s*[^.]*\.\s*(?:transfer|send|call))',
            'logic_before_transfer': r'(?:[^;]*;\s*[^=;]*\s*[=+-]\s*[^;]*;\s*[^.;]*\.\s*(?:transfer|send|call))',
            'assert_statements': r'assert\s*\(',
            'require_statements': r'require\s*\(',
            'event_logging': r'emit\s+\w+\s*\(',
        }
        
    def extract_features_from_contract(self, contract_code):
        """Extract enhanced features from a smart contract code"""
        features = {}
        
        # Contract size and structure features
        features['contract_size'] = len(contract_code)
        features['contract_lines'] = len(contract_code.split('\n'))
        features['avg_line_length'] = features['contract_size'] / max(features['contract_lines'], 1)
        
        # Count vulnerability patterns
        for vuln_name, pattern in self.vulnerability_patterns.items():
            try:
                features[f'has_{vuln_name}'] = 1 if re.search(pattern, contract_code, re.MULTILINE) else 0
                features[f'count_{vuln_name}'] = len(re.findall(pattern, contract_code, re.MULTILINE))
            except re.error:
                # Handle any regex errors gracefully
                print(f"Warning: Error in regex pattern for {vuln_name}. Skipping this pattern.")
                features[f'has_{vuln_name}'] = 0
                features[f'count_{vuln_name}'] = 0
            
        # Count security patterns
        for sec_name, pattern in self.security_patterns.items():
            try:
                features[f'has_{sec_name}'] = 1 if re.search(pattern, contract_code, re.MULTILINE) else 0
                features[f'count_{sec_name}'] = len(re.findall(pattern, contract_code, re.MULTILINE))
            except re.error:
                # Handle any regex errors gracefully
                print(f"Warning: Error in regex pattern for {sec_name}. Skipping this pattern.")
                features[f'has_{sec_name}'] = 0
                features[f'count_{sec_name}'] = 0
        
        # Code structure features
        features['function_count'] = len(re.findall(r'function\s+\w+\s*\(', contract_code))
        features['modifier_count'] = len(re.findall(r'modifier\s+\w+\s*\(', contract_code))
        features['event_count'] = len(re.findall(r'event\s+\w+\s*\(', contract_code))
        features['constructor_count'] = len(re.findall(r'constructor\s*\(|function\s+\w+\s*\(\s*\)\s*(?:public|external)?\s*(?:is|\{)', contract_code))
        
        # State variables and data structures
        features['state_var_count'] = len(re.findall(r'^\s*(uint|int|bool|address|string|bytes)\s+\w+', contract_code, re.MULTILINE))
        features['mapping_count'] = len(re.findall(r'mapping\s*\(', contract_code))
        features['array_count'] = len(re.findall(r'\[\s*\]', contract_code))
        features['struct_count'] = len(re.findall(r'struct\s+\w+', contract_code))
        
        # External calls and interactions
        features['external_call_count'] = len(re.findall(r'\.\w+\s*\(', contract_code))
        features['msg_value_usage'] = len(re.findall(r'msg\.value', contract_code))
        features['balance_check_count'] = len(re.findall(r'balance', contract_code))
        
        # Security operations
        features['if_count'] = len(re.findall(r'\bif\s*\(', contract_code))
        features['require_count'] = len(re.findall(r'require\s*\(', contract_code))
        features['assert_count'] = len(re.findall(r'assert\s*\(', contract_code))
        features['revert_count'] = len(re.findall(r'revert\s*\(', contract_code))
        
        # Function visibility
        features['public_func_count'] = len(re.findall(r'function\s+\w+\s*\([^)]*\)\s*public', contract_code))
        features['external_func_count'] = len(re.findall(r'function\s+\w+\s*\([^)]*\)\s*external', contract_code))
        features['internal_func_count'] = len(re.findall(r'function\s+\w+\s*\([^)]*\)\s*internal', contract_code))
        features['private_func_count'] = len(re.findall(r'function\s+\w+\s*\([^)]*\)\s*private', contract_code))
        
        # Security modifiers
        features['view_func_count'] = len(re.findall(r'function\s+\w+\s*\([^)]*\)\s*(?:public|external|internal|private)?\s*view', contract_code))
        features['pure_func_count'] = len(re.findall(r'function\s+\w+\s*\([^)]*\)\s*(?:public|external|internal|private)?\s*pure', contract_code))
        features['payable_func_count'] = len(re.findall(r'function\s+\w+\s*\([^)]*\)\s*(?:public|external)?\s*payable', contract_code))
        
        # Calculate important ratios
        try:
            features['security_check_ratio'] = (features['require_count'] + features['assert_count'] + features['revert_count']) / max(features['function_count'], 1)
            features['external_exposure_ratio'] = (features['public_func_count'] + features['external_func_count']) / max(features['function_count'], 1)
            features['payable_ratio'] = features['payable_func_count'] / max(features['public_func_count'] + features['external_func_count'], 1)
        except ZeroDivisionError:
            features['security_check_ratio'] = 0
            features['external_exposure_ratio'] = 0
            features['payable_ratio'] = 0
        
        # Use of common security libraries
        features['has_openzeppelin'] = 1 if re.search(r'openzeppelin|@openzeppelin', contract_code, re.IGNORECASE) else 0
        features['has_consensys'] = 1 if re.search(r'consensys', contract_code, re.IGNORECASE) else 0
        
        # Composite vulnerability scores
        features['vuln_patterns_total'] = sum([features[f'has_{v}'] for v in self.vulnerability_patterns.keys()])
        features['security_patterns_total'] = sum([features[f'has_{s}'] for s in self.security_patterns.keys()])
        features['security_score'] = features['security_patterns_total'] - features['vuln_patterns_total']
        
        return features
    
    def load_sample_data(self):
        """Load and prepare sample data from SmartBugs repository with improved balancing"""
        if not self.smartbugs_repo_path or not os.path.exists(self.smartbugs_repo_path):
            print(f"SmartBugs repo path not found. Using enhanced synthetic data.")
            return self._create_enhanced_synthetic_dataset()
            
        # In a real implementation, we would load and process the dataset from SmartBugs
        contracts_data = []
        
        # Process vulnerable contracts
        vulnerabilities_path = os.path.join(self.smartbugs_repo_path, "dataset")
        for vuln_type in os.listdir(vulnerabilities_path):
            vuln_dir = os.path.join(vulnerabilities_path, vuln_type)
            if os.path.isdir(vuln_dir):
                for contract_file in glob.glob(os.path.join(vuln_dir, "**/*.sol"), recursive=True):
                    try:
                        with open(contract_file, 'r', encoding='utf-8') as f:
                            code = f.read()
                            features = self.extract_features_from_contract(code)
                            features['code_text'] = code
                            features['is_vulnerable'] = 1
                            features['vulnerability_type'] = vuln_type
                            contracts_data.append(features)
                    except Exception as e:
                        print(f"Error processing {contract_file}: {e}")
        
        # Process non-vulnerable contracts
        safe_contracts_path = os.path.join(self.smartbugs_repo_path, "safe_contracts")
        if os.path.exists(safe_contracts_path):
            for contract_file in glob.glob(os.path.join(safe_contracts_path, "**/*.sol"), recursive=True):
                try:
                    with open(contract_file, 'r', encoding='utf-8') as f:
                        code = f.read()
                        features = self.extract_features_from_contract(code)
                        features['code_text'] = code
                        features['is_vulnerable'] = 0
                        features['vulnerability_type'] = 'none'
                        contracts_data.append(features)
                except Exception as e:
                    print(f"Error processing {contract_file}: {e}")
        
        df = pd.DataFrame(contracts_data)
        
        # Store feature names for later use
        self.feature_names = [col for col in df.columns if col not in ['code_text', 'is_vulnerable', 'vulnerability_type']]
        
        return df
    
    def _create_enhanced_synthetic_dataset(self):
        """Create an enhanced synthetic dataset with clear distinction between vulnerable and secure contracts"""
        np.random.seed(42)
        contracts_data = []
        
        # Generate synthetic vulnerable contracts with more realistic patterns
        vulnerability_types = ['reentrancy', 'timestamp_dependence', 'unchecked_send', 'tx_origin', 'integer_overflow', 
                              'delegatecall', 'unchecked_low_level_calls', 'dos_vulnerable']
        
        # Create diverse vulnerable contracts
        for i in range(200):
            vuln_type = np.random.choice(vulnerability_types)
            
            # Base contract template
            base_code = """
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;
            
            contract VulnerableContract {
                mapping(address => uint) private balances;
                address[] private users;
                address private owner;
                
                constructor() {
                    owner = msg.sender;
                }
            """
            
            # Add vulnerability based on type
            if vuln_type == 'reentrancy':
                vuln_code = """
                function deposit() public payable {
                    balances[msg.sender] += msg.value;
                }
                
                function withdraw(uint _amount) public {
                    require(balances[msg.sender] >= _amount);
                    (bool success, ) = msg.sender.call{value: _amount}("");
                    balances[msg.sender] -= _amount;
                }
                """
            elif vuln_type == 'timestamp_dependence':
                vuln_code = """
                function isLuckyDay() public view returns (bool) {
                    return (block.timestamp % 7 == 0);
                }
                
                function distributePrize() public {
                    if (isLuckyDay()) {
                        payable(msg.sender).transfer(1 ether);
                    }
                }
                """
            elif vuln_type == 'unchecked_send':
                vuln_code = """
                function withdrawAll() public {
                    uint amount = balances[msg.sender];
                    balances[msg.sender] = 0;
                    payable(msg.sender).send(amount);
                }
                """
            elif vuln_type == 'tx_origin':
                vuln_code = """
                function transferOwnership(address newOwner) public {
                    if (tx.origin == owner) {
                        owner = newOwner;
                    }
                }
                """
            elif vuln_type == 'integer_overflow':
                vuln_code = """
                function addToBalance(uint amount) public {
                    balances[msg.sender] += amount;
                }
                
                function increaseUserCount() public {
                    users.push(msg.sender);
                    uint userCount = users.length;
                    userCount++;
                }
                """
            elif vuln_type == 'delegatecall':
                vuln_code = """
                function execute(address _target, bytes memory _data) public {
                    _target.delegatecall(_data);
                }
                """
            elif vuln_type == 'unchecked_low_level_calls':
                vuln_code = """
                function sendFunds(address payable _receiver, uint _amount) public {
                    _receiver.call{value: _amount}("");
                }
                """
            elif vuln_type == 'dos_vulnerable':
                vuln_code = """
                function distributeRewards() public {
                    for(uint i = 0; i < users.length; i++) {
                        payable(users[i]).transfer(1 wei);
                    }
                }
                """
            else:
                vuln_code = """
                function vulnerable() public {
                    // Some vulnerable code
                }
                """
            
            # Complete the contract
            full_code = base_code + vuln_code + "\n}"
            
            # Extract features
            try:
                features = self.extract_features_from_contract(full_code)
                features['code_text'] = full_code
                features['is_vulnerable'] = 1
                features['vulnerability_type'] = vuln_type
                contracts_data.append(features)
            except Exception as e:
                print(f"Error processing synthetic vulnerable contract: {e}")
        
        # Create diverse secure contracts with proper security measures
        for i in range(200):
            # Generate a secure contract with different security patterns
            security_level = np.random.choice(['high', 'medium', 'standard'])
            
            if security_level == 'high':
                secure_code = """
                // SPDX-License-Identifier: MIT
                pragma solidity ^0.8.0;
                
                import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
                import "@openzeppelin/contracts/access/Ownable.sol";
                import "@openzeppelin/contracts/utils/math/SafeMath.sol";
                
                contract SecureContract is ReentrancyGuard, Ownable {
                    using SafeMath for uint256;
                    
                    mapping(address => uint256) private balances;
                    event Deposit(address indexed user, uint256 amount);
                    event Withdrawal(address indexed user, uint256 amount);
                    
                    function deposit() public payable {
                        require(msg.value > 0, "Amount must be greater than 0");
                        balances[msg.sender] = balances[msg.sender].add(msg.value);
                        emit Deposit(msg.sender, msg.value);
                    }
                    
                    function withdraw(uint256 _amount) public nonReentrant {
                        require(_amount > 0, "Amount must be greater than 0");
                        require(balances[msg.sender] >= _amount, "Insufficient balance");
                        
                        balances[msg.sender] = balances[msg.sender].sub(_amount);
                        emit Withdrawal(msg.sender, _amount);
                        
                        (bool success, ) = payable(msg.sender).call{value: _amount}("");
                        require(success, "Transfer failed");
                    }
                    
                    function getBalance() public view returns (uint256) {
                        return balances[msg.sender];
                    }
                }
                """
            elif security_level == 'medium':
                secure_code = """
                // SPDX-License-Identifier: MIT
                pragma solidity ^0.8.0;
                
                contract SecureContract {
                    address private owner;
                    mapping(address => uint) private balances;
                    
                    event Deposit(address user, uint amount);
                    event Withdrawal(address user, uint amount);
                    
                    constructor() {
                        owner = msg.sender;
                    }
                    
                    modifier onlyOwner() {
                        require(msg.sender == owner, "Not authorized");
                        _;
                    }
                    
                    function deposit() public payable {
                        require(msg.value > 0, "Amount must be greater than 0");
                        balances[msg.sender] += msg.value;
                        emit Deposit(msg.sender, msg.value);
                    }
                    
                    function withdraw(uint _amount) public {
                        require(_amount > 0, "Amount must be greater than 0");
                        require(balances[msg.sender] >= _amount, "Insufficient balance");
                        
                        balances[msg.sender] -= _amount;
                        emit Withdrawal(msg.sender, _amount);
                        
                        (bool success, ) = payable(msg.sender).call{value: _amount}("");
                        require(success, "Transfer failed");
                    }
                    
                    function changeOwner(address newOwner) public onlyOwner {
                        require(newOwner != address(0), "Invalid address");
                        owner = newOwner;
                    }
                }
                """
            else:  # standard security
                secure_code = """
                // SPDX-License-Identifier: MIT
                pragma solidity ^0.8.0;
                
                contract SecureContract {
                    address private owner;
                    mapping(address => uint) private balances;
                    
                    constructor() {
                        owner = msg.sender;
                    }
                    
                    function deposit() public payable {
                        require(msg.value > 0, "Amount must be greater than 0");
                        balances[msg.sender] += msg.value;
                    }
                    
                    function withdraw(uint _amount) public {
                        require(balances[msg.sender] >= _amount, "Insufficient balance");
                        balances[msg.sender] -= _amount;
                        payable(msg.sender).transfer(_amount);
                    }
                    
                    function getBalance() public view returns (uint) {
                        return balances[msg.sender];
                    }
                }
                """
            
            # Extract features
            try:
                features = self.extract_features_from_contract(secure_code)
                features['code_text'] = secure_code
                features['is_vulnerable'] = 0
                features['vulnerability_type'] = 'none'
                contracts_data.append(features)
            except Exception as e:
                print(f"Error processing synthetic secure contract: {e}")
            
        df = pd.DataFrame(contracts_data)
        
        # Store feature names for later use
        self.feature_names = [col for col in df.columns if col not in ['code_text', 'is_vulnerable', 'vulnerability_type']]
        
        return df
    
    def train_model(self):
        """Train a ML model with improved feature engineering and model selection"""
        # Load and prepare data
        try:
            df = self.load_sample_data()
            
            if df.empty:
                print("Error: No data available for training. Please check the dataset.")
                return None
            
            # Prepare text features using TF-IDF with improved parameters
            self.vectorizer = TfidfVectorizer(
                max_features=1500, 
                ngram_range=(1, 3),
                min_df=2,
                max_df=0.9,
                stop_words='english',
                token_pattern=r'(?u)\b\w+\b|\.|\(|\)|{|}|\[|\]|->|=>|\+\+|--|==|!=|>=|<=|&&|\|\|'
            )
            X_text = self.vectorizer.fit_transform(df['code_text'])
            
            # Prepare numeric features
            feature_cols = self.feature_names
            X_numeric = df[feature_cols].fillna(0).values
            
            # Combine features
            X_combined = np.hstack((X_text.toarray(), X_numeric))
            y = df['is_vulnerable'].values
            
            # Split data with stratification to maintain class balance
            X_train, X_test, y_train, y_test = train_test_split(
                X_combined, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Use Gradient Boosting for better performance
            print("Training advanced vulnerability detection model...")
            self.model = GradientBoostingClassifier(
                n_estimators=200,
                learning_rate=0.1,
                max_depth=5,
                min_samples_split=5,
                min_samples_leaf=2,
                max_features='sqrt',
                subsample=0.8,
                random_state=42
            )
            
            self.model.fit(X_train, y_train)
            
            # Evaluate model
            print("\nModel Training Complete!")
            train_predictions = self.model.predict(X_train)
            print("Training Performance:")
            print(classification_report(y_train, train_predictions))
            
            test_predictions = self.model.predict(X_test)
            print("\nTest Performance:")
            print(classification_report(y_test, test_predictions))
            
            # Show confusion matrix
            cm = confusion_matrix(y_test, test_predictions)
            print("\nConfusion Matrix:")
            print(cm)
            
            # Calculate feature importance for the top features
            if hasattr(self.model, 'feature_importances_'):
                importances = self.model.feature_importances_
                combined_features = list(self.vectorizer.get_feature_names_out()) + feature_cols
                if len(combined_features) == len(importances):
                    importance_df = pd.DataFrame({
                        'feature': combined_features,
                        'importance': importances
                    })
                    top_features = importance_df.sort_values('importance', ascending=False).head(20)
                    print("\nTop 20 Important Features:")
                    for idx, row in top_features.iterrows():
                        print(f"{row['feature']}: {row['importance']:.4f}")
            
            return self.model
            
        except Exception as e:
            print(f"Error during model training: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def save_model(self, model_path="smart_contract_vuln_model.pkl", vectorizer_path="tfidf_vectorizer.pkl"):
        """Save the trained model and vectorizer"""
        if self.model is None:
            print("No model to save. Please train the model first.")
            return False
        
        try:
            joblib.dump(self.model, model_path)
            joblib.dump(self.vectorizer, vectorizer_path)
            # Save feature names for consistency in loading
            with open("feature_names.json", "w") as f:
                json.dump({"feature_names": self.feature_names}, f)
                
            print(f"Model saved to {model_path}")
            print(f"Vectorizer saved to {vectorizer_path}")
            print(f"Feature names saved to feature_names.json")
            return True
        except Exception as e:
            print(f"Error saving model: {e}")
            return False
    
    def load_model(self, model_path="smart_contract_vuln_model.pkl", vectorizer_path="tfidf_vectorizer.pkl"):
        """Load a trained model and vectorizer"""
        try:
            if os.path.exists(model_path) and os.path.exists(vectorizer_path):
                self.model = joblib.load(model_path)
                self.vectorizer = joblib.load(vectorizer_path)
              
                # Load feature names if available
                if os.path.exists("feature_names.json"):
                    with open("feature_names.json", "r") as f:
                        feature_data = json.load(f)
                        self.feature_names = feature_data.get("feature_names", [])
                
                print(f"Model loaded from {model_path}")
                return True
            else:
                print(f"Model or vectorizer file not found. Training new model.")
                return self.train_model() is not None
        except Exception as e:
            print(f"Error loading model: {e}")
            print(f"Training new model.")
            return self.train_model() is not None
    
    def analyze_contract(self, contract_code=None, contract_file=None):
        """Analyze a smart contract for vulnerabilities with improved detection"""
        # Load contract code
        if contract_file and os.path.exists(contract_file):
            with open(contract_file, 'r', encoding='utf-8') as f:
                contract_code = f.read()
        elif not contract_code:
            print("Either contract_code or contract_file must be provided.")
            return None
        
        # Ensure model is loaded
        if self.model is None:
            self.load_model()
            if self.model is None:
                self.train_model()
        
        # Extract features
        features = self.extract_features_from_contract(contract_code)
        
        # Transform text using vectorizer
        X_text = self.vectorizer.transform([contract_code])
        
        # Prepare numeric features using the same order as during training
        if not self.feature_names:
            # If feature names not available, extract from features dict
            self.feature_names = [key for key in features.keys() if key != 'code_text']
            
        X_numeric = np.array([features.get(col, 0) for col in self.feature_names]).reshape(1, -1)
        
        # Combine features
        X_combined = np.hstack((X_text.toarray(), X_numeric))
        
        # Predict
        is_vulnerable = self.model.predict(X_combined)[0]
        vulnerability_prob = self.model.predict_proba(X_combined)[0][1]
        
        # Identify potential vulnerability types with detailed explanations
        potential_vulnerabilities = []
        vulnerability_details = {}
        
        for vuln_name, pattern in self.vulnerability_patterns.items():
            # Find all matches with line numbers
            matches = []
            for i, line in enumerate(contract_code.split('\n')):
                if re.search(pattern, line):
                    matches.append((i+1, line.strip()))
            
            if matches:
                potential_vulnerabilities.append(vuln_name)
                vulnerability_details[vuln_name] = {
                    'description': self._get_vulnerability_description(vuln_name),
                    'line_matches': matches,
                    'count': len(matches),
                    'severity': self._get_vulnerability_severity(vuln_name)
                }
        
        # Identify security features
        security_features = []
        for sec_name, pattern in self.security_patterns.items():
            if re.search(pattern, contract_code):
                security_features.append(sec_name)
        
        # Calculate weighted vulnerability score
        vuln_score = vulnerability_prob * 10  # Scale to 0-10
        
        # Adjust score based on security features
        security_adjustment = -0.5 * len(security_features)
        adjusted_score = max(0, min(10, vuln_score + security_adjustment))
        
        # Determine severity
        if adjusted_score > 7.5:
            severity = 'Critical'
        elif adjusted_score > 5:
            severity = 'High'
        elif adjusted_score > 2.5:
            severity = 'Medium'
        else:
            severity = 'Low'
        
        # Prepare detailed result
        result = {
            'is_vulnerable': bool(is_vulnerable),
            'vulnerability_probability': float(vulnerability_prob),
            'vulnerability_score': float(adjusted_score),
            'severity': severity,
            'potential_vulnerabilities': potential_vulnerabilities,
            'vulnerability_details': vulnerability_details,
            'security_features': security_features,
            'recommendations': self._generate_recommendations(potential_vulnerabilities, security_features)
        }
        
        return result
    
    def _get_vulnerability_description(self, vuln_name):
        """Get vulnerability description"""
        descriptions = {
            'reentrancy': 'Allows an attacker to repeatedly call back into the contract before previous execution completes, potentially draining funds.',
            'timestamp_dependence': 'Using block.timestamp as a condition for critical operations can be manipulated by miners within constraints.',
            'unchecked_send': 'Not checking the return value of send() or transfer() operations can lead to silent failures.',
            'unprotected_functions': 'Functions lacking proper access controls allow unauthorized users to execute critical operations.',
            'tx_origin': 'Using tx.origin for authorization allows phishing-style attacks between contracts.',
            'integer_overflow': 'Arithmetic operations can wrap around and cause unexpected behavior if not properly checked.',
            'unchecked_math': 'Mathematical operations without proper checks can lead to overflows, underflows, or division by zero.',
            'access_control': 'Missing or improper implementation of access control mechanisms.',
            'delegatecall': 'Using delegatecall with user-supplied inputs can lead to execution of malicious code within contract context.',
            'unchecked_low_level_calls': 'Low-level calls without proper checks can fail silently and lead to unexpected behavior.',
            'dos_vulnerable': 'Functions may be vulnerable to denial of service attacks through gas limitations or failed operations.',
            'use_of_suicide': 'Using selfdestruct or suicide makes the contract vulnerable to destructive attacks if not properly controlled.'
        }
        return descriptions.get(vuln_name, 'Potential security vulnerability detected in contract.')
    
    def _get_vulnerability_severity(self, vuln_name):
        """Get vulnerability severity level"""
        severities = {
            'reentrancy': 'Critical',
            'timestamp_dependence': 'Medium',
            'unchecked_send': 'High',
            'unprotected_functions': 'High',
            'tx_origin': 'High',
            'integer_overflow': 'Critical',
            'unchecked_math': 'High',
            'access_control': 'Critical',
            'delegatecall': 'Critical',
            'unchecked_low_level_calls': 'High',
            'dos_vulnerable': 'Medium',
            'use_of_suicide': 'Critical'
        }
        return severities.get(vuln_name, 'Medium')
    
    def _generate_recommendations(self, vulnerabilities, security_features):
        """Generate specific recommendations based on vulnerabilities and missing security features"""
        recommendations = []
        
        # Vulnerability-specific recommendations
        if 'reentrancy' in vulnerabilities:
            recommendations.append("Use a ReentrancyGuard modifier or implement the checks-effects-interactions pattern to prevent reentrancy attacks.")
        
        if 'timestamp_dependence' in vulnerabilities:
            recommendations.append("Avoid using block.timestamp or now for critical operations. If needed, consider using it only as a rough estimate of time.")
        
        if 'unchecked_send' in vulnerabilities or 'unchecked_low_level_calls' in vulnerabilities:
            recommendations.append("Always check the return value of low-level functions like send(), transfer(), and call(). Use require() statements to validate results.")
        
        if 'unprotected_functions' in vulnerabilities:
            recommendations.append("Implement proper access control using modifiers like onlyOwner or explicit validation with require(msg.sender == owner).")
        
        if 'tx_origin' in vulnerabilities:
            recommendations.append("Replace tx.origin with msg.sender for authorization checks to prevent phishing attacks.")
        
        if 'integer_overflow' in vulnerabilities or 'unchecked_math' in vulnerabilities:
            recommendations.append("Use SafeMath library or Solidity 0.8.0+ built-in overflow/underflow protection for arithmetic operations.")
        
        if 'delegatecall' in vulnerabilities:
            recommendations.append("Avoid delegatecall with user-supplied inputs or implement strict validation and whitelisting for allowed addresses.")
        
        if 'dos_vulnerable' in vulnerabilities:
            recommendations.append("Prevent DoS by using pull over push patterns for payments and implementing gas-efficient loops.")
        
        # Recommendations for missing security features
        if 'uses_safemath' not in security_features and ('integer_overflow' in vulnerabilities or 'unchecked_math' in vulnerabilities):
            recommendations.append("Implement SafeMath library for arithmetic operations or use Solidity 0.8.0+ which includes built-in overflow checks.")
        
        if 'uses_ownable' not in security_features and 'unprotected_functions' in vulnerabilities:
            recommendations.append("Consider using the OpenZeppelin Ownable contract to implement secure ownership management.")
        
        if 'uses_reentrancy_guard' not in security_features and 'reentrancy' in vulnerabilities:
            recommendations.append("Implement OpenZeppelin's ReentrancyGuard contract to protect against reentrancy attacks.")
        
        if 'uses_checks_effects_interactions' not in security_features:
            recommendations.append("Follow the checks-effects-interactions pattern: validate conditions, update state, and only then interact with external contracts.")
        
        if not recommendations:
            recommendations.append("Consider performing a comprehensive security audit to identify any potential vulnerabilities not detected by automated tools.")
        
        return recommendations

def main():
    parser = argparse.ArgumentParser(description='Smart Contract Vulnerability Detector')
    parser.add_argument('--contract', type=str, help='Path to smart contract (.sol) file')
    parser.add_argument('--repo', type=str, help='Path to SmartBugs repository (optional)')
    parser.add_argument('--train', action='store_true', help='Train a new model')
    parser.add_argument('--save', action='store_true', help='Save the trained model')
    parser.add_argument('--detailed', action='store_true', help='Show detailed vulnerability analysis')
    
    args = parser.parse_args()
    
    detector = SmartContractVulnerabilityDetector(args.repo)
    
    if args.train:
        detector.train_model()
        if args.save:
            detector.save_model()
    
    if args.contract:
        if not os.path.exists(args.contract):
            print(f"Contract file not found: {args.contract}")
            return
        
        print(f"\nAnalyzing contract: {args.contract}")
        result = detector.analyze_contract(contract_file=args.contract)
        
        print("\n======= Vulnerability Analysis Results =======")
        print(f"Vulnerable: {'Yes' if result['is_vulnerable'] else 'No'}")
        print(f"Vulnerability Probability: {result['vulnerability_probability']:.4f}")
        print(f"Vulnerability Score: {result['vulnerability_score']:.2f}/10")
        print(f"Severity: {result['severity']}")
        
        if result['potential_vulnerabilities']:
            print("\nPotential Vulnerabilities Detected:")
            for vuln in result['potential_vulnerabilities']:
                vuln_details = result['vulnerability_details'][vuln]
                print(f"- {vuln.upper()} ({vuln_details['severity']})")
                if args.detailed:
                    print(f"  Description: {vuln_details['description']}")
                    print(f"  Occurrences: {vuln_details['count']}")
                    print("  Line matches:")
                    for line_num, line_content in vuln_details['line_matches'][:3]:  # Show first 3 matches
                        print(f"    Line {line_num}: {line_content}")
                    if len(vuln_details['line_matches']) > 3:
                        print(f"    ... and {len(vuln_details['line_matches']) - 3} more")
        else:
            print("\nNo specific vulnerabilities detected.")
            
        if result['security_features']:
            print("\nSecurity Features Detected:")
            for feature in result['security_features']:
                print(f"- {feature}")
        
        print("\nRecommendations:")
        for i, rec in enumerate(result['recommendations'], 1):
            print(f"{i}. {rec}")
        
        print("\nNote: This analysis provides an automated assessment but cannot replace a manual security audit.")
    else:
        if not args.train:
            print("Please provide a contract file to analyze or use --train to train a new model.")
            parser.print_help()

if __name__ == "__main__":
    main()