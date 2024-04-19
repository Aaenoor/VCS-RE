#include <iostream>
#include <fstream>
#include <vector>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <algorithm> // Added for find_if
#include <string>
#include <cstring> // Added for strcmp

using namespace std;

// Structure to represent a commit
struct Commit {
    string hash;
    string timestamp;
    string message;
    string filename;
    string content;
};

// Class representing a simple version control system
class VersionControlSystem {
private:
    vector<Commit> commitHistory;

public:
    // Function to initialize a new repository
    void initializeRepository() {
        cout << "Repository initialized successfully." << endl;
    }

    // Function to commit changes to a file
    void commitChanges(const string& filename, const string& message) {
        string fileContent = readFileContent(filename);

        // Create a new commit
        Commit commit;
        commit.timestamp = getCurrentTime();
        commit.message = message;
        commit.filename = filename;
        commit.content = fileContent;
        commit.hash = calculateHash(commit);

        // Add commit to history
        commitHistory.push_back(commit);

        cout << "Changes committed to file '" << filename << "'." << endl;
    }

    // Function to view commit log
    vector<Commit> getCommitLog() {
        return commitHistory;
    }

    // Function to revert to a previous version of a file
    void revertToFile(const string& filename, const string& commitHash) {
        // Find the commit with the specified hash
        auto commitIt = find_if(commitHistory.rbegin(), commitHistory.rend(),
                               [filename, commitHash](const Commit& commit) {
                                   return commit.filename == filename && commit.hash == commitHash;
                               });

        if (commitIt != commitHistory.rend()) {
            // Revert the file to the state at the specified commit
            writeFileContent(filename, commitIt->content);
            cout << "File '" << filename << "' reverted to the state at commit hash: " << commitHash << "." << endl;
        } else {
            cout << "Error: Commit with hash '" << commitHash << "' for file '" << filename << "' not found." << endl;
        }
    }

    // Function to compare two commits and show the differences
    void compareCommits(const string& commitHash1, const string& commitHash2) {
        Commit commit1, commit2;

        // Find commit 1
        auto commitIt1 = find_if(commitHistory.begin(), commitHistory.end(),
                                [commitHash1](const Commit& commit) {
                                    return commit.hash == commitHash1;
                                });
        if (commitIt1 != commitHistory.end()) {
            commit1 = *commitIt1;
        } else {
            cout << "Error: Commit with hash '" << commitHash1 << "' not found." << endl;
            return;
        }

        // Find commit 2
        auto commitIt2 = find_if(commitHistory.begin(), commitHistory.end(),
                                [commitHash2](const Commit& commit) {
                                    return commit.hash == commitHash2;
                                });
        if (commitIt2 != commitHistory.end()) {
            commit2 = *commitIt2;
        } else {
            cout << "Error: Commit with hash '" << commitHash2 << "' not found." << endl;
            return;
        }

        // Perform diffing
        string diff = calculateDiff(commit1.content, commit2.content);
        cout << "Differences between commits " << commitHash1 << " and " << commitHash2 << ":" << endl;
        cout << diff << endl;
    }

private:
    // Function to calculate SHA-256 hash of a commit
    string calculateHash(const Commit& commit) {
        string dataToHash = commit.filename + commit.content + commit.timestamp + commit.message;
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, dataToHash.c_str(), dataToHash.length());
        SHA256_Final(hash, &sha256);
        stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << hex << setw(2) << setfill('0') << static_cast<int>(hash[i]);
        }
        return ss.str();
    }

    // Function to get current timestamp
    string getCurrentTime() {
        time_t now = time(0);
        tm* localTime = localtime(&now);
        stringstream ss;
        ss << put_time(localTime, "%Y-%m-%d %X");
        return ss.str();
    }

    // Function to read file content
    string readFileContent(const string& filename) {
        ifstream fileStream(filename);
        stringstream buffer;
        buffer << fileStream.rdbuf();
        return buffer.str();
    }

    // Function to write content to a file
    void writeFileContent(const string& filename, const string& content) {
        ofstream fileStream(filename);
        fileStream << content;
    }

    // Function to calculate differences between two strings (basic diffing algorithm)
    string calculateDiff(const string& str1, const string& str2) {
        string diff;
        if (str1 == str2) {
            diff = "No differences found. Files are identical.";
        } else {
            diff = "Differences found:\n";
            diff += "----------\n";
            diff += "File 1:\n" + str1 + "\n";
            diff += "----------\n";
            diff += "File 2:\n" + str2 + "\n";
            diff += "----------\n";
        }
        return diff;
    }
};

int main() {
    VersionControlSystem vcs;

    // Initialize repository
    vcs.initializeRepository();

    // Make changes to the file
    ofstream fileStream("example.txt");
    fileStream << "Initial content.";

    // Commit changes
    vcs.commitChanges("example.txt", "Initial commit");

    // Make more changes to the file
    fileStream << " Additional content.";

    // Commit changes
    vcs.commitChanges("example.txt", "Second commit");

    // View commit log
    vector<Commit> commitLog = vcs.getCommitLog();
    for (const auto& commit : commitLog) {
        cout << "Hash: " << commit.hash << " | Timestamp: " << commit.timestamp
             << " | Message: " << commit.message << " | Filename: " << commit.filename << endl;
    }

    // Compare two commits
    if (commitLog.size() >= 2) {
        vcs.compareCommits(commitLog[0].hash, commitLog[1].hash);
    }

    return 0;
}
