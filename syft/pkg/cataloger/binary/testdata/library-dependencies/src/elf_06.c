extern const char *syft_06_identity(void);
int main(void) {
    return syft_06_identity()[0] == 's' ? 0 : 1;
}
