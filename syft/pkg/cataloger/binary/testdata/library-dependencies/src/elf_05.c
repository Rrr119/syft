extern const char *syft_05_identity(void);
int main(void) {
    return syft_05_identity()[0] == 's' ? 0 : 1;
}
